import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ise_client import _normalize_rule, _parse_other_attributes, _parse_records  # noqa: E402

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
