"""Convert an LLM "Automated Code & Security Audit Report" (Markdown) to SARIF.

Usage:
  llm-audit-to-sarif REPORT.md             # writes REPORT.sarif, no upload
  llm-audit-to-sarif REPORT.md --upload    # also uploads to code scanning

The upload uses the `gh` CLI. It sends the SARIF for the head commit of the
report's "Reference" branch, under the category `llm-audit-<branch>`. A finding
that is missing from a later upload in the same category closes automatically.
"""

import argparse
import base64
import gzip
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

# Report priority -> (SARIF level, GitHub security-severity score)
PRIORITY = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.5"),
    "low": ("warning", "2.0"),
    "info": ("note", "0.0"),
}
GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")
PATH_LINE = re.compile(r"^(?P<path>[^\s:]+?)(?::(?P<line>\d+))?$")


def parse_metadata(md):
    meta = {}
    for key, value in re.findall(r"^- \*\*(.+?):\*\*\s*`?([^`\n]*)`?\s*$", md, re.MULTILINE):
        meta[key.strip()] = value.strip()
    return meta


def parse_findings(md):
    """Return the rows of the table under '## Findings' as dicts."""
    section = re.search(r"^## Findings\s*$(.*?)(?=^## |\Z)", md, re.MULTILINE | re.DOTALL)
    if not section:
        raise SystemExit("No '## Findings' section in the report.")
    rows = []
    for line in section.group(1).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 4 or set(cells[0]) <= set("-: ") or cells[0].lower() == "priority":
            continue
        # ponytail: a '|' inside the description is rejoined, a '|' in other cells is not supported
        rows.append(
            {
                "priority": cells[0],
                "type": cells[1],
                "path": cells[2],
                "description": "|".join(cells[3:]),
            }
        )
    return rows


def location(path_cell):
    """First path of the cell, as (uri, line). 'a.py:12; b.py' or 'a.py:12, b.py' -> ('a.py', 12)."""
    first = re.split(r"[;,]", path_cell)[0].strip().strip("`").split()[0]
    first = first.rstrip(".").rstrip("/")  # "backend/tests/..." -> "backend/tests"
    m = PATH_LINE.match(first)
    if not m:
        raise SystemExit(f"cannot read a path from the Path cell: {path_cell!r}")
    return m.group("path"), int(m.group("line") or 1)


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def to_sarif(md):
    rules, results = {}, []
    for row in parse_findings(md):
        level, score = PRIORITY.get(row["priority"].lower(), ("warning", "5.5"))
        ghsa = GHSA.search(row["description"])
        rule_id = ghsa.group(0) if ghsa else f"llm-audit/{slug(row['type'])}"
        uri, line = location(row["path"])
        rule = rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": slug(row["type"]),
                "shortDescription": {"text": row["type"]},
                "properties": {"tags": ["security"], "security-severity": score},
            },
        )
        # A rule shared by several rows keeps the highest severity.
        if float(score) > float(rule["properties"]["security-severity"]):
            rule["properties"]["security-severity"] = score
        if ghsa:
            rule["helpUri"] = f"https://github.com/advisories/{rule_id}"
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"[{row['priority']}] {row['description']}\n\nPaths: {row['path']}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": line},
                        }
                    }
                ],
                # Stable across runs, so an unchanged finding keeps the same alert.
                "partialFingerprints": {
                    "llmAudit/v1": hashlib.sha256(f"{rule_id}|{uri}".encode()).hexdigest()
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "llm-audit", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def gh(*args, stdin=None):
    # stderr is not captured, so a gh error (401, 403, 404) shows in the terminal.
    done = subprocess.run(["gh", *args], input=stdin, stdout=subprocess.PIPE, text=True)
    if done.returncode:
        sys.exit(f"gh {args[0]} failed with exit code {done.returncode}.")
    return done.stdout


def upload(sarif, repo, branch):
    sha = gh("api", f"repos/{repo}/commits/{branch}", "--jq", ".sha").strip()
    # The upload API has no category field: SARIF automationDetails.id is the category.
    sarif["runs"][0]["automationDetails"] = {"id": f"llm-audit-{branch}/"}
    body = {
        "commit_sha": sha,
        "ref": f"refs/heads/{branch}",
        "sarif": base64.b64encode(gzip.compress(json.dumps(sarif).encode())).decode(),
        "tool_name": "llm-audit",
    }
    out = gh(
        "api",
        "-X",
        "POST",
        f"repos/{repo}/code-scanning/sarifs",
        "--input",
        "-",
        stdin=json.dumps(body),
    )
    print(f"Uploaded for {branch} @ {sha[:12]}: {out.strip()}")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("report", type=Path)
    p.add_argument("-o", "--output", type=Path, help="SARIF file (default: REPORT.sarif)")
    p.add_argument("--upload", action="store_true", help="upload to GitHub code scanning with gh")
    p.add_argument("--repo", help="owner/name (default: from the report's Repository line)")
    p.add_argument("--branch", help="branch (default: from the report's Reference line)")
    a = p.parse_args()

    md = a.report.read_text()
    meta = parse_metadata(md)
    sarif = to_sarif(md)
    out = a.output or a.report.with_suffix(".sarif")
    out.write_text(json.dumps(sarif, indent=2) + "\n")
    print(f"Wrote {len(sarif['runs'][0]['results'])} findings to {out}")

    if a.upload:
        repo = a.repo or re.sub(r"^https://github.com/|\.git$", "", meta.get("Repository", ""))
        branch = a.branch or meta.get("Reference")
        if not repo or not branch:
            sys.exit("Cannot find the repository or branch. Pass --repo and --branch.")
        upload(sarif, repo, branch)


if __name__ == "__main__":
    main()
