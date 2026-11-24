from llm_audit_to_sarif import cli
from llm_audit_to_sarif.cli import json_pages, location, parse_metadata, to_sarif

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
    assert location("`a.py:1001`, `b.py:395`") == ("a.py", 1001)
    try:
        location("a.py:x")
        raise AssertionError("expected SystemExit")
    except SystemExit as e:
        assert "a.py:x" in str(e)


def test_fingerprint_is_stable():
    assert results()[0]["partialFingerprints"] == results()[0]["partialFingerprints"]


def test_json_pages():
    assert json_pages("[1,2][3]\n") == [1, 2, 3]
    assert json_pages('{"id": "abc"}') == {"id": "abc"}


def test_gitlab_issues_sync(monkeypatch):
    """Open what is new, keep what is known, close what is gone, skip below the minimum."""
    high, low, info = results()
    gone = "0" * 64
    existing = [
        # Below the minimum, but still in the report: not closed.
        issue(4, "opened", f"<!-- llm-audit:main:{info['partialFingerprints']['llmAudit/v1']} -->"),
        issue(1, "opened", f"<!-- llm-audit:main:{high['partialFingerprints']['llmAudit/v1']} -->"),
        issue(2, "opened", f"<!-- llm-audit:main:{gone} -->"),
        issue(3, "opened", f"<!-- llm-audit:dev:{gone} -->"),  # other branch: not touched
    ]
    calls = []

    def fake_glab(host, method, path, body=None):
        if method == "GET":
            return {"id": "f" * 40} if "/commits/" in path else existing
        calls.append((method, path.split("/", 2)[2], body))
        return {"iid": 9, "title": body.get("title")}

    monkeypatch.setattr(cli, "glab", fake_glab)
    cli.sync_gitlab_issues(to_sarif(REPORT), "gitlab.example.com", "group/project", "main")

    opened = [body for method, path, body in calls if (method, path) == ("POST", "issues")]
    assert len(opened) == 1  # the Low row. High is known, Info is below the minimum.
    assert opened[0]["confidential"] is True
    assert low["partialFingerprints"]["llmAudit/v1"] in opened[0]["description"]
    assert [path for method, path, _ in calls if method == "PUT"] == ["issues/2"]


def issue(iid, state, description):
    return {"iid": iid, "state": state, "description": description, "labels": [], "title": "t"}
