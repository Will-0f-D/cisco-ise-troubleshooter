import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio  # noqa: E402

import ise_client  # noqa: E402
from ise_client import (  # noqa: E402
    _enrich,
    _mac,
    _merge_active_session,
    _normalize_rule,
    _parse_other_attributes,
    _parse_records,
)

SINGLE = """<?xml version="1.0"?>
<sessionParameters>
    <acs_server>ise-pan-01</acs_server>
    <user_name>jdoe</user_name>
    <calling_station_id>00:11:22:33:44:55</calling_station_id>
    <nas_ip_address>10.0.0.1</nas_ip_address>
    <session_status>AUTHENTICATED</session_status>
</sessionParameters>
"""

LIST = """<?xml version="1.0"?>
<sessionList>
    <sessionParameters><user_name>jdoe</user_name></sessionParameters>
    <sessionParameters><user_name>asmith</user_name></sessionParameters>
</sessionList>
"""

EMPTY = """<?xml version="1.0"?>
<sessionList/>
"""

MALFORMED = "not xml at all <<<"

# AuthStatus-style response: no confirmed "sessionParameters" wrapper tag,
# falls back to treating each record-like child as one record.
AUTHSTATUS_FALLBACK = """<?xml version="1.0"?>
<authStatusList>
    <authRecord><user_name>jdoe</user_name><failure_reason>22056 Subject not found</failure_reason></authRecord>
    <authRecord><user_name>jdoe</user_name><failure_reason>passed</failure_reason></authRecord>
</authStatusList>
"""

# Single flat record with no children at all beyond leaves, no wrapper.
FLAT_SINGLE = """<?xml version="1.0"?>
<result><status>true</status></result>
"""

# Forma reale di AuthStatus/MACAddress (schema fullRESTAuthStatusOutputList):
# tre livelli di wrapper e un authStatusElements per tentativo.
AUTHSTATUS_REAL = """<?xml version="1.0"?>
<authStatusOutputList>
  <authStatusList key="00:0C:29:46:F3:B8">
    <authStatusElements>
      <passed>false</passed>
      <failed>true</failed>
      <user_name>suser77</user_name>
      <failure_reason>22056 Subject not found</failure_reason>
      <other_attributes>ConfigVersionId=81,IdentityPolicyMatchedRule=Default</other_attributes>
    </authStatusElements>
    <authStatusElements>
      <passed>true</passed>
      <failed>false</failed>
      <user_name>suser77</user_name>
      <identity_policy_matched_rule>Dot1X</identity_policy_matched_rule>
      <authorization_policy>CWA_Redirect</authorization_policy>
      <selected_azn_profiles>CWA_Redirect</selected_azn_profiles>
    </authStatusElements>
  </authStatusList>
</authStatusOutputList>
"""

ACTIVE_LIST = """<?xml version="1.0"?>
<activeList noOfActiveSession="2">
  <activeSession><user_name>jdoe</user_name><server>ise-psn-01</server></activeSession>
  <activeSession><user_name>asmith</user_name><server>ise-psn-02</server></activeSession>
</activeList>
"""


def test_parses_single_session():
    result = _parse_records(SINGLE)
    assert len(result) == 1
    assert result[0]["user_name"] == "jdoe"
    assert result[0]["calling_station_id"] == "00:11:22:33:44:55"


def test_parses_session_list():
    result = _parse_records(LIST)
    assert len(result) == 2
    assert {r["user_name"] for r in result} == {"jdoe", "asmith"}


def test_empty_list_returns_empty():
    assert _parse_records(EMPTY) == []


def test_malformed_xml_returns_empty():
    assert _parse_records(MALFORMED) == []


def test_fallback_to_generic_record_children():
    result = _parse_records(AUTHSTATUS_FALLBACK)
    assert len(result) == 2
    assert result[0]["failure_reason"] == "22056 Subject not found"


def test_fallback_to_root_as_single_record():
    result = _parse_records(FLAT_SINGLE)
    assert result == [{"status": "true"}]


def test_authstatus_returns_every_attempt_flat():
    """Regressione: i tre livelli di wrapper collassavano in un solo record con i
    campi annidati sotto 'authStatusElements', perdendo tutti i tentativi tranne l'ultimo."""
    result = _parse_records(AUTHSTATUS_REAL)
    assert len(result) == 2
    assert result[0]["failure_reason"] == "22056 Subject not found"
    assert result[0]["passed"] == "false"
    assert result[1]["identity_policy_matched_rule"] == "Dot1X"
    assert result[1]["authorization_policy"] == "CWA_Redirect"
    assert "authStatusElements" not in result[0]


def test_authstatus_exposes_policy_names_from_other_attributes():
    result = _parse_records(AUTHSTATUS_REAL)
    assert result[0]["other_attributes_parsed"]["IdentityPolicyMatchedRule"] == "Default"
    # Il secondo record non ha il blob: nessuna chiave inventata.
    assert "other_attributes_parsed" not in result[1]


def test_parses_active_session_list():
    result = _parse_records(ACTIVE_LIST)
    assert [r["user_name"] for r in result] == ["jdoe", "asmith"]


def test_other_attributes_values_may_contain_commas_and_equals():
    parsed = _parse_other_attributes(
        "AuthorizationPolicyMatchedRule=CWA_Redirect,"
        "Response=url-redirect=https://x/portal?a=1,b=2,"
        "ISEPolicySetName=Default"
    )
    assert parsed["AuthorizationPolicyMatchedRule"] == "CWA_Redirect"
    assert parsed["ISEPolicySetName"] == "Default"
    assert parsed["Response"].startswith("url-redirect=https://x/portal?a=1")


def test_mac_normalized_to_ise_format():
    """ISE accetta solo maiuscolo/XX:XX:...: un formato diverso risponde 'nessuna
    sessione' invece di dare errore, e le colonne restano vuote senza spiegazione."""
    assert _mac("00:0c:29:46:f3:b8") == "00:0C:29:46:F3:B8"
    assert _mac("000c.2946.f3b8") == "00:0C:29:46:F3:B8"
    assert _mac("00-0C-29-46-F3-B8") == "00:0C:29:46:F3:B8"
    # Input non riconoscibile: non va reinventato, passa così com'è.
    assert _mac(" non-un-mac ") == "NON-UN-MAC"


def test_merge_active_session_picks_matching_audit_session():
    """Stesso MAC, due sessioni: si sceglie per audit_session_id, non la prima."""
    brief = {"user_name": "jdoe", "calling_station_id": "00:11:22:33:44:55",
             "audit_session_id": "0A00000100000002", "server": "ise-psn-02"}
    detail = [
        {"audit_session_id": "0A00000100000001", "passed": "false", "authorization_policy": "Guest"},
        {"audit_session_id": "0A00000100000002", "passed": "true", "authorization_policy": "Corp"},
    ]
    merged = _merge_active_session(brief, detail)
    assert merged["authorization_policy"] == "Corp"
    assert merged["passed"] == "true"
    # I campi di ActiveList restano quelli della lista sessioni attive.
    assert merged["server"] == "ise-psn-02"


def test_merge_active_session_without_detail_invents_nothing():
    brief = {"user_name": "jdoe", "calling_station_id": "00:11:22:33:44:55"}
    assert _merge_active_session(brief, []) == brief


def test_merge_active_session_keeps_detail_when_brief_field_empty():
    merged = _merge_active_session({"user_name": ""}, [{"user_name": "jdoe", "passed": "true"}])
    assert merged["user_name"] == "jdoe"


def test_other_attributes_real_policy_names():
    """Valori reali da ISE: il nome della regola contiene spazi e trattini, e alcune
    chiavi ISE contengono uno spazio ('Device Type'): senza ammetterlo finivano
    dentro il valore della chiave precedente."""
    parsed = _parse_other_attributes(
        "ConfigVersionId=145,"
        "IdentityPolicyMatchedRule=WiFi PEAP - SDA Mobile-Workstation - AuthC,"
        "AuthorizationPolicyMatchedRule=WiFi_Dipendenti_PEAP_Mobile,"
        "EndPointMACAddress=00-0C-29-46-F3-B8,"
        "Device Type=Device Type#All Device Types#WLC,"
        "Location=Location#All Locations#Milano"
    )
    assert parsed["IdentityPolicyMatchedRule"] == "WiFi PEAP - SDA Mobile-Workstation - AuthC"
    assert parsed["AuthorizationPolicyMatchedRule"] == "WiFi_Dipendenti_PEAP_Mobile"
    assert parsed["EndPointMACAddress"] == "00-0C-29-46-F3-B8"
    assert parsed["Device Type"] == "Device Type#All Device Types#WLC"
    assert parsed["Location"] == "Location#All Locations#Milano"


ATTR_STRING_EXAMPLE = (
    ":!:AuthenticationStatus=AuthenticationPassed"
    ":!:IdentityPolicyMatchedRule=Wireless MAB"
    ":!:AuthorizationPolicyMatchedRule=GuestDemanio-Auth-ISE02"
    ":!:ISEPolicySetName=SSID Guest Agenzie"
    ":!:IdentitySelectionMatchedRule=Wireless MAB"
)


def test_other_attr_string_split_on_delimiter():
    """other_attr_string usa ':!:' come separatore: spezzare sui singoli ':'
    romperebbe valori che li contengono."""
    parsed = _enrich({"other_attr_string": ATTR_STRING_EXAMPLE})["other_attributes_parsed"]
    assert parsed["IdentityPolicyMatchedRule"] == "Wireless MAB"
    assert parsed["AuthorizationPolicyMatchedRule"] == "GuestDemanio-Auth-ISE02"
    assert parsed["ISEPolicySetName"] == "SSID Guest Agenzie"
    # Chiave omonima ma diversa: non deve prendere il posto della regola di autenticazione.
    assert parsed["IdentitySelectionMatchedRule"] == "Wireless MAB"


def test_other_attr_string_value_keeps_extra_equals_and_colons():
    parsed = _enrich({"other_attr_string": ":!:Response=url-redirect=https://ise:8443/portal?x=1:!:Foo=bar"})["other_attributes_parsed"]
    assert parsed["Response"] == "url-redirect=https://ise:8443/portal?x=1"
    assert parsed["Foo"] == "bar"


def test_missing_or_empty_attr_blob_adds_no_keys():
    for record in ({}, {"other_attr_string": ""}, {"other_attr_string": None}, {"other_attr_string": ":!::!:"}):
        assert "other_attributes_parsed" not in _enrich(dict(record))


SESSION_WITH_ATTR_STRING = """<?xml version="1.0"?>
<sessionParameters>
    <user_name>guest01</user_name>
    <calling_station_id>00:0C:29:46:F3:B8</calling_station_id>
    <other_attr_string>{}</other_attr_string>
</sessionParameters>
""".format(ATTR_STRING_EXAMPLE)


def test_session_response_exposes_rules_from_attr_string():
    """Stesso percorso usato dal tab Diagnostica (Session/MACAddress) e dalle
    sessioni attive: le regole devono uscire dal blob gia' in _parse_records."""
    record = _parse_records(SESSION_WITH_ATTR_STRING)[0]
    parsed = record["other_attributes_parsed"]
    assert parsed["IdentityPolicyMatchedRule"] == "Wireless MAB"
    assert parsed["AuthorizationPolicyMatchedRule"] == "GuestDemanio-Auth-ISE02"
    assert record["user_name"] == "guest01"


def test_auth_status_bulk_tags_mac_and_isolates_failures(monkeypatch):
    """AuthStatus interroga un MAC alla volta: un MAC che va in errore non deve
    far sparire i tentativi degli altri, altrimenti sembra 'nessun fallimento'."""
    async def fake(host, user, pwd, mac, seconds, records, attrs, verify_ssl, port):
        if mac == "00:00:00:00:00:BAD":
            raise RuntimeError("timeout MNT")
        return [{"passed": "false", "failed": "true", "failure_reason": "22056"}]

    monkeypatch.setattr(ise_client, "get_auth_status", fake)
    rows = asyncio.run(ise_client.get_auth_status_bulk(
        "h", "u", "p", ["00:11:22:33:44:55", "00:00:00:00:00:BAD"]))
    assert rows[0]["_mac"] == "00:11:22:33:44:55"
    assert rows[0]["failed"] == "true"
    assert rows[1] == {"_mac": "00:00:00:00:00:BAD", "_error": "timeout MNT"}


def test_auth_status_bulk_caps_the_number_of_calls(monkeypatch):
    calls = []

    async def fake(host, user, pwd, mac, seconds, records, attrs, verify_ssl, port):
        calls.append(mac)
        return []

    monkeypatch.setattr(ise_client, "get_auth_status", fake)
    asyncio.run(ise_client.get_auth_status_bulk("h", "u", "p", [f"m{i}" for i in range(150)]))
    assert len(calls) == ise_client.AUTHSTATUS_BULK_LIMIT


def test_normalize_rule_reads_state_from_nested_rule():
    item = {"rule": {"id": "r1", "name": "FMC Admin", "state": "enabled", "rank": 0, "default": False},
            "profile": ["FMC-Admin"], "securityGroup": None}
    assert _normalize_rule(item) == {
        "id": "r1", "name": "FMC Admin", "state": "enabled", "rank": 0, "default": False,
        "profiles": ["FMC-Admin"], "security_group": None, "identity_source": None,
    }


def test_normalize_rule_wraps_device_admin_string_profile():
    item = {"rule": {"name": "Default"}, "profile": "Deny All Shell Profile"}
    assert _normalize_rule(item)["profiles"] == ["Deny All Shell Profile"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("OK")


def test_enrich_prefers_structured_and_keeps_the_discrepancy():
    """Le due rappresentazioni dello stesso attributo non si sovrascrivono in
    silenzio: vince other_attributes, ma la differenza resta consultabile."""
    record = _enrich({
        "other_attributes": "AuthorizationPolicyMatchedRule=Corp, ISEPolicySetName=Wired",
        "other_attr_string": "AuthorizationPolicyMatchedRule=Guest:!:UseCase=Host Lookup",
    })
    parsed = record["other_attributes_parsed"]
    assert parsed["AuthorizationPolicyMatchedRule"] == "Corp"
    assert parsed["UseCase"] == "Host Lookup", "il blob resta il fallback per le chiavi mancanti"
    assert record["other_attributes_sources"]["AuthorizationPolicyMatchedRule"] == "other_attributes"
    assert record["other_attributes_sources"]["UseCase"] == "other_attr_string"
    assert record["other_attributes_conflicts"] == [{
        "key": "AuthorizationPolicyMatchedRule",
        "other_attributes": "Corp",
        "other_attr_string": "Guest",
    }]


def test_enrich_accepts_other_attributes_as_object():
    """Alcuni percorsi consegnano other_attributes gia' strutturato: va usato com'e',
    senza tentare di riparsarlo come blob."""
    record = _enrich({"other_attributes": {"ISEPolicySetName": "SSID Guest Agenzie"}})
    assert record["other_attributes_parsed"]["ISEPolicySetName"] == "SSID Guest Agenzie"


def test_enrich_reports_no_conflict_when_both_agree():
    record = _enrich({
        "other_attributes": "UseCase=Host Lookup",
        "other_attr_string": "UseCase=Host Lookup",
    })
    assert "other_attributes_conflicts" not in record
