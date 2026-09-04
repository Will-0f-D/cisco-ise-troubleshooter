import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ise_client import _parse_records  # noqa: E402

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


if __name__ == "__main__":
    test_parses_single_session()
    test_parses_session_list()
    test_empty_list_returns_empty()
    test_malformed_xml_returns_empty()
    test_fallback_to_generic_record_children()
    test_fallback_to_root_as_single_record()
    print("OK")
