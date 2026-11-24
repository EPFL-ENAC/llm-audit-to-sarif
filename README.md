# llm-audit-to-sarif

Convert an LLM security audit report (Markdown) to SARIF, and upload it to GitHub code scanning. For a GitLab project, keep one confidential issue per finding.

SARIF (Static Analysis Results Interchange Format) is the JSON format that GitHub code scanning reads. After the upload, each finding is an alert in the Security tab of the repository. You can then triage it, dismiss it, or let it close automatically.

## Requirements

- [uv](https://docs.astral.sh/uv/).
- [GitHub CLI](https://cli.github.com/) (`gh`), logged in with write access to code scanning on the target repository.
- For GitLab issues only: [GitLab CLI](https://gitlab.com/gitlab-org/cli) (`glab`), logged in to the GitLab host as a member of the target project.

## Usage

Run the tool from any directory. You do not need to clone this repository.

```bash
uvx --from git+https://github.com/EPFL-ENAC/llm-audit-to-sarif llm-audit-to-sarif job-1234-report.md
```

This writes `job-1234-report.sarif` next to the report and does not upload it. Read the file before the upload.

To upload, add `--upload`:

```bash
uvx --from git+https://github.com/EPFL-ENAC/llm-audit-to-sarif llm-audit-to-sarif job-1234-report.md --upload
```

The tool reads the repository from the `Repository` line of the report, and the branch from the `Reference` line. To override them, use `--repo owner/name` and `--branch name`.

If the `GH_TOKEN` environment variable holds an expired token, `gh` uses it instead of your keyring login, and the upload fails with HTTP 401. In that case, run the command with `env -u GH_TOKEN` in front of it.

## How the upload works

- The SARIF goes to the head commit of the branch at upload time. The report does not give the commit that the scanner saw. Upload soon after the scan, before the branch moves.
- Each branch gets its own category, `llm-audit-<branch>`. If a finding is missing from a later upload in the same category, GitHub closes its alert.
- The alert fingerprint is the rule and the file path. A finding with the same rule and path keeps the same alert across scans.

## GitLab issues

GitLab has a vulnerability report only on the Ultimate tier. For the other tiers, the tool keeps one issue per finding. It calls the GitLab API from your machine and does not need a CI job.

```bash
uvx --from git+https://github.com/EPFL-ENAC/llm-audit-to-sarif llm-audit-to-sarif job-1234-report.md \
  --gitlab-issues gitlab.example.com/group/project
```

The branch comes from the `Reference` line of the report. To override it, use `--branch name`. The branch must exist in the GitLab project.

Each issue is confidential. Only project members with the Planner role or higher can see a confidential issue. That is also true in a public project.

Each run does these actions:

- A new finding opens an issue with the labels `llm-audit`, `severity:<priority>` and `branch:<branch>`.
- A known finding keeps its issue. The run creates no duplicate.
- A finding that is missing from the report closes its issue, with a note and the label `llm-audit:fixed`.
- A finding that comes back reopens the issue that the tool closed.
- An issue that a person closed stays closed. Close an issue by hand to dismiss its finding.

Each branch has its own set of issues. Two findings with the same rule and the same path share one issue.

Findings with the priority Info do not open an issue. To change the lowest priority that opens an issue, use `--min-priority`, for example `--min-priority info`. The minimum only stops a new issue. A finding that already has an issue keeps it.

Each new issue sends a notification to the project members.

## Report format

The tool reads the `## Metadata` list and the table under `## Findings`. Other sections are ignored.

```markdown
## Findings
| Priority | Type | Path | Description |
|---|---|---|---|
| High | Dependency (OSV) | backend/uv.lock | dnspython 2.9.0 (GHSA-vvf4-9x63-8xvv) ... |
| Low | Authorization | backend/app/core/policy.py:316 | ... |
```

| Report value | SARIF result |
|---|---|
| Priority Critical or High | level `error` |
| Priority Medium or Low | level `warning` |
| Priority Info | level `note` |
| A GHSA ID in Description | rule ID is the GHSA ID, with a link to the advisory |
| No GHSA ID | rule ID is `llm-audit/<type>` |
| Path `file:line` | location at that line |
| Path list `a; b` | location at the first path, line 1 |

A path that is a directory, or a phrase such as "backend/app and backend/tests", gives an alert with no code view.

## Development

```bash
uv run --extra dev pytest
uv run --extra dev ruff check .
```
