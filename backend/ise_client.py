"""Thin client for the Cisco ISE MNT (Monitoring) REST API.

Uses the same admin-credential-authenticated API the ISE GUI's "Live Logs"
page calls under the hood: https://<ise>/admin/API/mnt/...

Endpoints verified against Cisco DevNet docs and community threads:
- Session/*, AuthStatus/* : https://developer.cisco.com/docs/identity-services-engine/latest/using-api-calls-for-troubleshooting/
- CoA/Reauth               : official DevNet example (Using Change of Authorization REST APIs)
- CoA/Disconnect           : community-reported format only, not in official docs -
                              behavior has been reported to vary between ISE patch levels.
"""
import xml.etree.ElementTree as ET

import httpx


class IseConnectionError(Exception):
    """Network-level failure talking to ISE (host unreachable, TLS, timeout)."""


class IseAuthError(Exception):
    """ISE reachable but credentials were rejected."""


def _flatten(elem: ET.Element) -> dict:
    return {child.tag: (_flatten(child) if len(child) else (child.text or "").strip()) for child in elem}


def _parse_records(xml_text: str) -> list[dict]:
    """Flatten ISE MNT XML into a list of dicts, tolerant of the exact wrapper tag."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    records = [_flatten(e) for e in root.iter("sessionParameters")]
    if records:
        return records
    children_with_subelements = [c for c in root if len(c)]
    if children_with_subelements:
        return [_flatten(c) for c in children_with_subelements]
    if len(root):
        return [_flatten(root)]
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


async def get_session_by_mac(host: str, username: str, password: str, mac: str, verify_ssl: bool = False, port: int | None = None) -> list[dict]:
    resp = await _mnt_get(host, username, password, f"Session/MACAddress/{mac}", verify_ssl, port)
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


async def get_active_sessions(host: str, username: str, password: str, verify_ssl: bool = False, port: int | None = None) -> list[dict]:
    resp = await _mnt_get(host, username, password, "Session/ActiveList", verify_ssl, port)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return _parse_records(resp.text)


async def get_auth_status(
    host: str, username: str, password: str, mac: str,
    seconds: int = 86400, records: int = 20, attrs: str = "All",
    verify_ssl: bool = False, port: int | None = None,
) -> list[dict]:
    """RADIUS authentication attempts (pass + fail) for a MAC, including failure_reason."""
    resp = await _mnt_get(host, username, password, f"AuthStatus/MACAddress/{mac}/{seconds}/{records}/{attrs}", verify_ssl, port)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return _parse_records(resp.text)


async def coa_reauth(
    host: str, username: str, password: str, psn_name: str, mac: str,
    reauth_type: int = 0, verify_ssl: bool = False, port: int | None = None,
) -> str:
    """reauth_type: 0=default, 1=last, 2=rerun."""
    resp = await _mnt_get(host, username, password, f"CoA/Reauth/{psn_name}/{mac}/{reauth_type}", verify_ssl, port)
    resp.raise_for_status()
    return resp.text.strip()


async def coa_disconnect(
    host: str, username: str, password: str, mnt_node: str, mac: str,
    switch_ip: str, psn_ip: str, disconnect_type: int = 0,
    verify_ssl: bool = False, port: int | None = None,
) -> str:
    """disconnect_type: 0=default, 1=port-bounce, 2=disconnect. Community-reported format."""
    resp = await _mnt_get(host, username, password, f"CoA/Disconnect/{mnt_node}/{mac}/{disconnect_type}/{switch_ip}/{psn_ip}", verify_ssl, port)
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
    search = await _ers_get(host, username, password, f"endpoint?filter=mac.EQ.{mac}", verify_ssl, port)
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
