from llm_audit_to_sarif.cli import location, parse_metadata, to_sarif

REPORT = """# Automated Code & Security Audit Report

## Metadata

- **Repository:** `https://github.com/epfl-enac/example`
- **Reference:** `main`

## Findings
| Priority | Type | Path | Description |
|---|---|---|---|
| High | Dependency (OSV) | backend/uv.lock | dnspython 2.9.0 (GHSA-vvf4-9x63-8xvv, CVSS 7.5) |
| Low | Authorization | backend/app/core/policy.py:316 | fail-open a|b |
| Info | Secret scan | a.py; backend/tests/... | false positive |

## Prioritization
| not | a | finding | row |
"""


def results():
    return to_sarif(REPORT)["runs"][0]["results"]


def uri_line(result):
    loc = result["locations"][0]["physicalLocation"]
    return loc["artifactLocation"]["uri"], loc["region"]["startLine"]


def test_metadata():
    meta = parse_metadata(REPORT)
    assert meta["Reference"] == "main"
    assert meta["Repository"] == "https://github.com/epfl-enac/example"


def test_only_findings_table_rows():
    assert len(results()) == 3


def test_ghsa_becomes_rule_id():
    first = results()[0]
    assert first["ruleId"] == "GHSA-vvf4-9x63-8xvv"
    assert first["level"] == "error"


def test_path_with_line_and_pipe_in_description():
    second = results()[1]
    assert uri_line(second) == ("backend/app/core/policy.py", 316)
    assert "fail-open a|b" in second["message"]["text"]


def test_first_path_of_a_list():
    third = results()[2]
    assert third["level"] == "note"
    assert uri_line(third) == ("a.py", 1)
    assert location("backend/tests/...") == ("backend/tests", 1)


def test_fingerprint_is_stable():
    assert results()[0]["partialFingerprints"] == results()[0]["partialFingerprints"]
