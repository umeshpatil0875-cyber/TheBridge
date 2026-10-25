# SecureBridge report

**Verdict: BLOCKED** (9 blocking, 1 waived)

## Scanners

| Scanner | Status | Detail |
| --- | --- | --- |
| gitleaks | demo | 1 finding(s) from sample output |
| semgrep | demo | 3 finding(s) from sample output |
| trivy | demo | 7 finding(s) from sample output |

## Findings by severity

| Severity | Count |
| --- | --- |
| critical | 4 |
| high | 6 |
| medium | 1 |

## All findings

| Severity | Kind | Where | What | Fix | Blocks? |
| --- | --- | --- | --- | --- | --- |
| critical | dependency | requirements.txt | requests: Authorization header sent to a different host on redirect (CVE-2018-18074) | Upgrade requests to 2.20.0 or newer. | yes |
| critical | dependency | requirements.txt | PyYAML: arbitrary code execution when loading untrusted YAML (CVE-2020-14343) | Upgrade pyyaml to 5.4 or newer. | yes |
| critical | dependency | requirements.txt | PyYAML: arbitrary code execution via FullLoader (CVE-2020-1747) | Upgrade pyyaml to 5.3.1 or newer. | yes |
| critical | dependency | requirements.txt | Jinja2: code injection in the from_string function (CVE-2019-8341) | Upgrade jinja2 to 2.10.1 or newer. | yes |
| high | config | Dockerfile:1 | Image user should not be 'root' (DS002) | Add 'USER <non root user name>' line to the Dockerfile | yes |
| high | code | app.py:20 | tainted sql string (python.flask.security.injection.tainted-sql-string.tainted-sql-string) | User input is used to build an SQL string. Use parameterized queries instead. | yes |
| high | code | app.py:28 | subprocess shell true (python.lang.security.audit.subprocess-shell-true.subprocess-shell-true) | Found 'subprocess' call with shell=True. This allows command injection. Pass a list of arguments and drop shell=True. | yes |
| high | secret | config.py:5 | GitHub Personal Access Token (github-pat) | Revoke and rotate the secret, then load it from an environment variable or a secrets manager instead. | yes |
| high | dependency | requirements.txt | Flask: denial of service via crafted JSON data (CVE-2018-1000656) | Upgrade flask to 0.12.3 or newer. | no |
| high | dependency | requirements.txt | Jinja2: sandbox escape through str.format_map (CVE-2019-10906) | Upgrade jinja2 to 2.10.1 or newer. | yes |
| medium | code | app.py:33 | debug enabled (python.flask.security.audit.debug-enabled.debug-enabled) | Running Flask with debug=True can expose an interactive console. Turn it off in production. | no |

## Waived (known and accepted)

- CVE-2018-1000656 in requirements.txt: Example waiver: the demo app does not accept JSON from users. Revisit after upgrading Flask. (expires 2026-12-31)
