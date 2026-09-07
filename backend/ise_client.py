"""Thin client for the Cisco ISE MNT (Monitoring) REST API.

Uses the same admin-credential-authenticated API the ISE GUI's "Live Logs"
page calls under the hood: https://<ise>/admin/API/mnt/...

Endpoints verified against Cisco DevNet docs and community threads:
- Session/*, AuthStatus/* : https://developer.cisco.com/docs/identity-services-engine/latest/using-api-calls-for-troubleshooting/
- CoA/Reauth               : official DevNet example (Using Change of Authorization REST APIs)
- CoA/Disconnect           : community-reported format only, not in official docs -
                              behavior has been reported to vary between ISE patch levels.
"""
import asyncio
import re
import xml.etree.ElementTree as ET

import httpx


class IseConnectionError(Exception):
    """Network-level failure talking to ISE (host unreachable, TLS, timeout)."""


class IseAuthError(Exception):
    """ISE reachable but credentials were rejected."""


def _flatten(elem: ET.Element) -> dict:
    return {child.tag: (_flatten(child) if len(child) else (child.text or "").strip()) for child in elem}


# Tag che contengono un singolo record, per endpoint MNT (schemi Cisco DevNet):
#   Session/MACAddress|UserName|IPAddress -> sessionParameters (è la radice stessa)
#   Session/ActiveList                    -> activeList > activeSession
#   AuthStatus/MACAddress                 -> authStatusOutputList > authStatusList > authStatusElements
#   AcctStatus/MACAddress                 -> acctStatusList > acctStatusElements
# AuthStatus/AcctStatus annidano su tre livelli: fermarsi al primo figlio con
# sotto-elementi restituirebbe un solo record con i campi un livello troppo in
# basso, perdendo per giunta tutti i record tranne l'ultimo (tag omonimi).
_RECORD_TAGS = ("sessionParameters", "activeSession", "authStatusElements", "acctStatusElements")

# Blob "key=value,key=value" di other_attributes. Il valore può contenere virgole
# e '=' (es. url-redirect), quindi si spezza solo prima di una chiave riconoscibile.
# Alcune chiavi ISE contengono uno spazio ("Device Type", "Model Name", "Software
# Version"): senza ammetterlo finiscono dentro il valore della chiave precedente.
_OTHER_ATTR_KEY = re.compile(r"(?:^|,)\s*([A-Za-z0-9_.\-]+(?: [A-Za-z0-9_.\-]+)*)=")


def _parse_other_attributes(blob: str) -> dict:
    """ISE impacchetta qui i nomi delle regole applicate (AuthorizationPolicyMatchedRule,
    IdentityPolicyMatchedRule, ISEPolicySetName...) quando non li emette come tag XML."""
    matches = list(_OTHER_ATTR_KEY.finditer(blob))
    out = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(blob)
        out[m.group(1)] = blob[m.end():end].strip()
    return out


# other_attr_string usa un delimitatore esplicito ":!:" invece della virgola. È il
# formato in cui ISE riporta davvero le regole applicate, e va spezzato solo su ":!:":
# i singoli ':' compaiono dentro i valori.
ATTR_STRING_SEP = ":!:"

# Campi in cui ISE impacchetta gli attributi dell'evento come blob chiave=valore.
_ATTR_BLOB_FIELDS = ("other_attributes", "other_attr_string")


def _parse_attr_string(blob: str) -> dict:
    """Segmenti separati da ':!:', ciascuno chiave=valore.

    Si spezza solo al primo '=': il valore può contenerne altri (url-redirect,
    Response=...). Segmenti vuoti o senza '=' vengono ignorati senza errori.
    """
    out = {}
    for segment in blob.split(ATTR_STRING_SEP):
        key, sep, value = segment.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def _parse_attr_blob(blob: str) -> dict:
    """Sceglie il formato in base al delimitatore realmente presente nel blob."""
    return _parse_attr_string(blob) if ATTR_STRING_SEP in blob else _parse_other_attributes(blob)


def _enrich(record: dict) -> dict:
    """Espande i blob di attributi in other_attributes_parsed.

    Qui vivono i nomi delle regole applicate all'evento (IdentityPolicyMatchedRule,
    AuthorizationPolicyMatchedRule, ISEPolicySetName): ISE spesso non li emette come
    tag XML dedicati. Un blob assente, nullo o vuoto non produce nessuna chiave: un
    attributo mancante resta mancante, non diventa un valore vuoto.
    """
    parsed = {}
    for field in _ATTR_BLOB_FIELDS:
        blob = record.get(field)
        if isinstance(blob, str) and "=" in blob:
            parsed.update(_parse_attr_blob(blob))
    if parsed:
        record["other_attributes_parsed"] = parsed
    return record


def _parse_records(xml_text: str) -> list[dict]:
    """Flatten ISE MNT XML into a list of dicts, tolerant of the exact wrapper tag."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    for tag in _RECORD_TAGS:
        records = [_flatten(e) for e in root.iter(tag)]
        if records:
            return [_enrich(r) for r in records]
    children_with_subelements = [c for c in root if len(c)]
    if children_with_subelements:
        return [_enrich(_flatten(c)) for c in children_with_subelements]
    if len(root):
        return [_enrich(_flatten(root))]
    return []


async def _mnt_get(host: str, username: str, password: str, path: str, verify_ssl: bool, port: int | None = None, timeout: float = 15.0) -> httpx.Response:
    netloc = f"{host}:{port}" if port else host
    url = f"https://{netloc}/admin/API/mnt/{path}"
    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            resp = await client.get(url, auth=(username, password), headers={"Accept": "application/xml"})
    except httpx.ConnectTimeout as e:
        raise IseConnectionError(f"Timeout di connessione verso {netloc}") from e
    except httpx.ConnectError as e:
        raise IseConnectionError(f"Impossibile raggiungere {netloc}: {e}") from e
    except httpx.TimeoutException as e:
        raise IseConnectionError(f"Timeout nella richiesta a {netloc}") from e
    if resp.status_code == 401:
        raise IseAuthError("Credenziali ISE rifiutate (401)")
    return resp


async def test_connection(host: str, username: str, password: str, verify_ssl: bool = False, port: int | None = None) -> bool:
    resp = await _mnt_get(host, username, password, "Session/ActiveCount", verify_ssl, port)
    resp.raise_for_status()
    return True


def _mac(mac: str) -> str:
    """ISE accetta il MAC solo maiuscolo e nel formato XX:XX:XX:XX:XX:XX.

    Un MAC minuscolo o in notazione Cisco (aabb.ccdd.eeff) non produce un errore:
    ISE risponde "nessuna sessione", indistinguibile da un MAC davvero assente.
    """
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hexs) == 12:
        return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)).upper()
    return mac.strip().upper()


async def get_session_by_mac(host: str, username: str, password: str, mac: str, verify_ssl: bool = False, port: int | None = None) -> list[dict]:
    resp = await _mnt_get(host, username, password, f"Session/MACAddress/{_mac(mac)}", verify_ssl, port)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return _parse_records(resp.text)


async def get_session_by_username(host: str, username: str, password: str, identity: str, verify_ssl: bool = False, port: int | None = None) -> list[dict]:
    resp = await _mnt_get(host, username, password, f"Session/UserName/{identity}", verify_ssl, port)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return _parse_records(resp.text)


# Session/ActiveList usa lo schema simpleActiveSession: 6 campi soli, senza
# passed/failed e senza i nomi delle regole. L'unico modo documentato da Cisco per
# avere gli attributi completi di una sessione attiva è rileggerla da
# Session/MACAddress (schema restsdStatus). È una chiamata per sessione: tetto
# massimo e concorrenza limitata per non sommergere il MNT.
ACTIVE_ENRICH_LIMIT = 200


def _merge_active_session(brief: dict, detail: list[dict]) -> dict:
    """Sovrappone il record completo alla voce ridotta di ActiveList.

    Se il MAC ha più sessioni si sceglie quella con lo stesso audit_session_id:
    è l'unico identificativo comune ai due schemi. I campi di ActiveList
    restano autorevoli, ma solo se valorizzati.
    """
    if not detail:
        return brief
    audit = brief.get("audit_session_id")
    match = next((d for d in detail if audit and d.get("audit_session_id") == audit), detail[0])
    return {**match, **{k: v for k, v in brief.items() if v}}


async def get_active_sessions(
    host: str, username: str, password: str, verify_ssl: bool = False,
    port: int | None = None, enrich: bool = True,
) -> list[dict]:
    resp = await _mnt_get(host, username, password, "Session/ActiveList", verify_ssl, port)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    sessions = _parse_records(resp.text)
    if not enrich:
        return sessions

    gate = asyncio.Semaphore(8)

    async def full(brief: dict) -> dict:
        mac = brief.get("calling_station_id")
        if not mac:
            return brief
        async with gate:
            try:
                detail = await get_session_by_mac(host, username, password, mac, verify_ssl, port)
            except Exception:
                return brief  # dettaglio non recuperabile: il dato resta assente, non inventato
        return _merge_active_session(brief, detail)

    enriched = await asyncio.gather(*[full(s) for s in sessions[:ACTIVE_ENRICH_LIMIT]])
    return [*enriched, *sessions[ACTIVE_ENRICH_LIMIT:]]


async def get_auth_status(
    host: str, username: str, password: str, mac: str,
    seconds: int = 86400, records: int = 20, attrs: str = "All",
    verify_ssl: bool = False, port: int | None = None,
) -> list[dict]:
    """RADIUS authentication attempts (pass + fail) for a MAC, including failure_reason."""
    resp = await _mnt_get(host, username, password, f"AuthStatus/MACAddress/{_mac(mac)}/{seconds}/{records}/{attrs}", verify_ssl, port)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return _parse_records(resp.text)


# AuthStatus interroga un MAC alla volta: non esiste una variante "tutti gli
# endpoint". Per vedere i tentativi falliti di più MAC si itera, con lo stesso
# tetto e la stessa concorrenza usati per l'arricchimento delle sessioni attive.
AUTHSTATUS_BULK_LIMIT = 100


async def get_auth_status_bulk(
    host: str, username: str, password: str, macs: list[str],
    seconds: int = 86400, records: int = 20,
    verify_ssl: bool = False, port: int | None = None,
) -> list[dict]:
    """Tentativi (riusciti e falliti) per una lista di MAC, ognuno marcato con _mac.

    Un MAC che fallisce la chiamata non blocca gli altri: produce una riga
    {"_mac": ..., "_error": ...} così la UI può dirlo invece di mostrare il vuoto.
    """
    gate = asyncio.Semaphore(8)

    async def one(mac: str) -> list[dict]:
        async with gate:
            try:
                found = await get_auth_status(host, username, password, mac, seconds, records, "All", verify_ssl, port)
            except Exception as e:
                return [{"_mac": mac, "_error": str(e)}]
        return [{**r, "_mac": mac} for r in found]

    batches = await asyncio.gather(*[one(m) for m in macs[:AUTHSTATUS_BULK_LIMIT] if m])
    return [r for batch in batches for r in batch]


async def coa_reauth(
    host: str, username: str, password: str, psn_name: str, mac: str,
    reauth_type: int = 0, verify_ssl: bool = False, port: int | None = None,
) -> str:
    """reauth_type: 0=default, 1=last, 2=rerun."""
    resp = await _mnt_get(host, username, password, f"CoA/Reauth/{psn_name}/{_mac(mac)}/{reauth_type}", verify_ssl, port)
    resp.raise_for_status()
    return resp.text.strip()


async def coa_disconnect(
    host: str, username: str, password: str, mnt_node: str, mac: str,
    switch_ip: str, psn_ip: str, disconnect_type: int = 0,
    verify_ssl: bool = False, port: int | None = None,
) -> str:
    """disconnect_type: 0=default, 1=port-bounce, 2=disconnect. Community-reported format."""
    resp = await _mnt_get(host, username, password, f"CoA/Disconnect/{mnt_node}/{_mac(mac)}/{disconnect_type}/{switch_ip}/{psn_ip}", verify_ssl, port)
    resp.raise_for_status()
    return resp.text.strip()


async def _openapi_get(host: str, username: str, password: str, path: str, verify_ssl: bool, port: int | None = None, timeout: float = 15.0) -> httpx.Response:
    """Cisco ISE Open API (distinct from ERS/MNT): deployment info, licensing, system settings."""
    netloc = f"{host}:{port}" if port else host
    url = f"https://{netloc}/api/v1/{path}"
    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            resp = await client.get(url, auth=(username, password), headers={"Accept": "application/json"})
    except httpx.ConnectTimeout as e:
        raise IseConnectionError(f"Timeout di connessione verso {netloc}") from e
    except httpx.ConnectError as e:
        raise IseConnectionError(f"Impossibile raggiungere {netloc}: {e}") from e
    except httpx.TimeoutException as e:
        raise IseConnectionError(f"Timeout nella richiesta a {netloc}") from e
    if resp.status_code == 401:
        raise IseAuthError("Credenziali rifiutate (401) per l'Open API - è abilitata in Administration > System > API Settings?")
    return resp


async def get_deployment_nodes(host: str, username: str, password: str, verify_ssl: bool = False, port: int | None = None) -> list[dict]:
    """All nodes in the ISE deployment/cluster, via the Open API (not ERS/MNT)."""
    resp = await _openapi_get(host, username, password, "deployment/node", verify_ssl, port)
    resp.raise_for_status()
    return resp.json().get("response", [])


async def get_license_status(host: str, username: str, password: str, verify_ssl: bool = False, port: int | None = None) -> dict:
    """Tier compliance, evaluation license, and Smart Licensing registration state.

    Each sub-call is independent: if the Open API is disabled or one endpoint fails,
    the others still return so the UI can show partial data instead of nothing.
    """
    result = {}
    for key, path in (
        ("tier_state", "license/system/tier-state"),
        ("eval_license", "license/system/eval-license"),
        ("registration", "license/system/register"),
    ):
        try:
            resp = await _openapi_get(host, username, password, path, verify_ssl, port)
            resp.raise_for_status()
            result[key] = resp.json()
        except Exception as e:
            result[key] = {"error": str(e)}
    return result


POLICY_STACKS = ("network-access", "device-admin")


def _normalize_rule(item: dict) -> dict:
    """Una regola OpenAPI: lo stato sta in rule.state, non nel livello esterno.

    'profile' è una lista per network-access e una stringa per device-admin.
    """
    rule = item.get("rule") or {}
    profile = item.get("profile")
    if isinstance(profile, str):
        profile = [profile]
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "state": rule.get("state"),
        "rank": rule.get("rank"),
        "default": rule.get("default"),
        "profiles": profile or [],
        "security_group": item.get("securityGroup"),
        "identity_source": item.get("identitySourceName"),
    }


async def get_policy_catalog(
    host: str, username: str, password: str, stack: str = "network-access",
    verify_ssl: bool = False, port: int | None = None,
) -> dict:
    """Configurazione dei policy set e delle relative regole via Open API.

    Restituisce SOLO la configurazione corrente: non dice nulla su cosa sia stato
    applicato a una sessione passata, né sull'esito di un'autenticazione. Lo stato
    'enabled' di una regola significa che la regola è attiva in configurazione.
    """
    if stack not in POLICY_STACKS:
        raise ValueError(f"stack non valido: {stack}")

    resp = await _openapi_get(host, username, password, f"policy/{stack}/policy-set", verify_ssl, port)
    resp.raise_for_status()
    policy_sets = resp.json().get("response", [])

    # Un policy set = 2 chiamate. Concorrenza limitata per non sommergere il PAN.
    gate = asyncio.Semaphore(5)

    async def rules(ps_id: str, kind: str) -> tuple[list[dict] | None, str | None]:
        async with gate:
            try:
                r = await _openapi_get(host, username, password, f"policy/{stack}/policy-set/{ps_id}/{kind}", verify_ssl, port)
                r.raise_for_status()
                return [_normalize_rule(i) for i in r.json().get("response", [])], None
            except Exception as e:
                return None, str(e)

    results = await asyncio.gather(*[
        rules(ps.get("id"), kind) for ps in policy_sets for kind in ("authentication", "authorization")
    ])

    out = []
    for i, ps in enumerate(policy_sets):
        (authn, authn_err), (authz, authz_err) = results[2 * i], results[2 * i + 1]
        out.append({
            "id": ps.get("id"), "name": ps.get("name"), "state": ps.get("state"),
            "rank": ps.get("rank"), "default": ps.get("default"), "description": ps.get("description"),
            "service_name": ps.get("serviceName"),
            "authentication": authn, "authentication_error": authn_err,
            "authorization": authz, "authorization_error": authz_err,
        })
    return {"stack": stack, "policy_sets": out}


async def _ers_get(host: str, username: str, password: str, path: str, verify_ssl: bool, port: int | None = None, timeout: float = 15.0) -> httpx.Response:
    netloc = f"{host}:{port}" if port else host
    url = f"https://{netloc}/ers/config/{path}"
    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            resp = await client.get(url, auth=(username, password), headers={"Accept": "application/json"})
    except httpx.ConnectTimeout as e:
        raise IseConnectionError(f"Timeout di connessione ERS verso {netloc}") from e
    except httpx.ConnectError as e:
        raise IseConnectionError(f"Impossibile raggiungere ERS su {netloc}: {e}") from e
    except httpx.TimeoutException as e:
        raise IseConnectionError(f"Timeout nella richiesta ERS a {netloc}") from e
    if resp.status_code == 401:
        raise IseAuthError("Credenziali ERS rifiutate (401) - l'account ha i permessi ERS?")
    return resp


async def get_endpoint_context(host: str, username: str, password: str, mac: str, verify_ssl: bool = False, port: int | None = None) -> dict | None:
    """Profiling/identity-group context for a MAC via ERS. Returns None if the endpoint is unknown to ISE."""
    search = await _ers_get(host, username, password, f"endpoint?filter=mac.EQ.{_mac(mac)}", verify_ssl, port)
    if search.status_code == 404:
        return None
    search.raise_for_status()
    resources = search.json().get("SearchResult", {}).get("resources", [])
    if not resources:
        return None
    detail = await _ers_get(host, username, password, f"endpoint/{resources[0]['id']}", verify_ssl, port)
    detail.raise_for_status()
    ep = detail.json().get("ERSEndPoint", {})

    group_name = None
    group_id = ep.get("groupId")
    if group_id:
        try:
            g = await _ers_get(host, username, password, f"endpointgroup/{group_id}", verify_ssl, port)
            if g.status_code == 200:
                group_name = g.json().get("EndPointGroup", {}).get("name")
        except Exception:
            pass  # nice-to-have enrichment, endpoint context is still useful without it

    return {
        "mac": ep.get("mac"),
        "identity_group": group_name or group_id,
        "static_group_assignment": ep.get("staticGroupAssignment"),
        "static_profile_assignment": ep.get("staticProfileAssignment"),
        "profile_id": ep.get("profileId"),
        "portal_user": ep.get("portalUser"),
    }
