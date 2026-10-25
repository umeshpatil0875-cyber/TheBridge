# SecureBridge report

**Verdict: BLOCKED** (11 blocking, 1 waived)

## Scanners

| Scanner | Status | Detail |
| --- | --- | --- |
| gitleaks | demo | 1 finding(s) from sample output |
| semgrep | demo | 3 finding(s) from sample output |
| trivy | demo | 9 finding(s) from sample output |

## Layers (from code to production)

| # | Layer | Status | Findings | Worst | Checked by |
| --- | --- | --- | --- | --- | --- |
| 1 | Source code | DEFECTIVE | 4 | high | gitleaks, semgrep |
| 2 | Dependencies | DEFECTIVE | 6 | critical | trivy |
| 3 | CI/CD pipeline | not scanned | 0 | - | nobody (no scanner for this layer yet) |
| 4 | Container image | DEFECTIVE | 1 | high | trivy |
| 5 | Infrastructure as code | DEFECTIVE | 1 | critical | trivy |
| 6 | Kubernetes | DEFECTIVE | 1 | high | trivy |
| 7 | Running system | not scanned | 0 | - | nobody (no scanner for this layer yet) |

**Defective layers:** Source code, Dependencies, Container image, Infrastructure as code, Kubernetes. Start fixing at **Source code**, the earliest broken layer, because problems upstream often carry downstream.

**Not scanned:** CI/CD pipeline, Running system. These layers may have problems this report cannot see.

## Findings by severity

| Severity | Count |
| --- | --- |
| critical | 5 |
| high | 7 |
| medium | 1 |

## All findings

| Severity | Layer | Kind | Where | What | Fix | Blocks? |
| --- | --- | --- | --- | --- | --- | --- |
| critical | Infrastructure as code | config | infra/main.tf:5 | Security group allows unrestricted ingress from the internet (AVD-AWS-0107) | Set a more restrictive cidr range. | yes |
| critical | Dependencies | dependency | requirements.txt | requests: Authorization header sent to a different host on redirect (CVE-2018-18074) | Upgrade requests to 2.20.0 or newer. | yes |
| critical | Dependencies | dependency | requirements.txt | PyYAML: arbitrary code execution when loading untrusted YAML (CVE-2020-14343) | Upgrade pyyaml to 5.4 or newer. | yes |
| critical | Dependencies | dependency | requirements.txt | PyYAML: arbitrary code execution via FullLoader (CVE-2020-1747) | Upgrade pyyaml to 5.3.1 or newer. | yes |
| critical | Dependencies | dependency | requirements.txt | Jinja2: code injection in the from_string function (CVE-2019-8341) | Upgrade jinja2 to 2.10.1 or newer. | yes |
| high | Container image | config | Dockerfile:1 | Image user should not be 'root' (DS002) | Add 'USER <non root user name>' line to the Dockerfile | yes |
| high | Source code | code | app.py:20 | tainted sql string (python.flask.security.injection.tainted-sql-string.tainted-sql-string) | User input is used to build an SQL string. Use parameterized queries instead. | yes |
| high | Source code | code | app.py:28 | subprocess shell true (python.lang.security.audit.subprocess-shell-true.subprocess-shell-true) | Found 'subprocess' call with shell=True. This allows command injection. Pass a list of arguments and drop shell=True. | yes |
| high | Source code | secret | config.py:5 | GitHub Personal Access Token (github-pat) | Revoke and rotate the secret, then load it from an environment variable or a secrets manager instead. | yes |
| high | Kubernetes | config | k8s/deployment.yaml:16 | Privileged container (KSV017) | Change 'containers[].securityContext.privileged' to 'false'. | yes |
| high | Dependencies | dependency | requirements.txt | Flask: denial of service via crafted JSON data (CVE-2018-1000656) | Upgrade flask to 0.12.3 or newer. | no |
| high | Dependencies | dependency | requirements.txt | Jinja2: sandbox escape through str.format_map (CVE-2019-10906) | Upgrade jinja2 to 2.10.1 or newer. | yes |
| medium | Source code | code | app.py:33 | debug enabled (python.flask.security.audit.debug-enabled.debug-enabled) | Running Flask with debug=True can expose an interactive console. Turn it off in production. | no |

## Waived (known and accepted)

- CVE-2018-1000656 in requirements.txt: Example waiver: the demo app does not accept JSON from users. Revisit after upgrading Flask. (expires 2026-12-31)
