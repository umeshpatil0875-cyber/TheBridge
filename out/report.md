# SecureBridge report

**Verdict: BLOCKED** (15 blocking, 1 waived)

## Scanners

| Scanner | Status | Detail |
| --- | --- | --- |
| gitleaks | ok | 1 finding(s) |
| semgrep | ok | 14 finding(s) |
| trivy | ok | 40 finding(s) |

## Layers (from code to production)

| # | Layer | Status | Findings | Worst | Checked by |
| --- | --- | --- | --- | --- | --- |
| 1 | Source code | DEFECTIVE | 10 | high | gitleaks, semgrep |
| 2 | Dependencies | DEFECTIVE | 17 | critical | trivy |
| 3 | CI/CD pipeline | not scanned | 0 | - | nobody (no scanner for this layer yet) |
| 4 | Container image | DEFECTIVE | 1 | high | trivy |
| 5 | Infrastructure as code | DEFECTIVE | 3 | high | trivy |
| 6 | Kubernetes | DEFECTIVE | 3 | high | trivy |
| 7 | Running system | not scanned | 0 | - | nobody (no scanner for this layer yet) |

**Defective layers:** Source code, Dependencies, Container image, Infrastructure as code, Kubernetes. Start fixing at **Source code**, the earliest broken layer, because problems upstream often carry downstream.

**Not scanned:** CI/CD pipeline, Running system. These layers may have problems this report cannot see.

## Findings by severity

| Severity | Count |
| --- | --- |
| critical | 2 |
| high | 14 |
| medium | 13 |
| low | 5 |

21 duplicate finding(s) from different tools were merged.

## All findings

| Severity | Layer | Kind | Where | What | Fix | Blocks? |
| --- | --- | --- | --- | --- | --- | --- |
| critical | Dependencies | dependency | requirements.txt | PyYAML: incomplete fix for CVE-2020-1747 (CVE-2020-14343) | Upgrade pyyaml to 5.4 or newer. | yes |
| critical | Dependencies | dependency | requirements.txt | PyYAML: arbitrary command execution through python/object/new when FullLoader is used (CVE-2020-1747) | Upgrade pyyaml to 5.3.1 or newer. | yes |
| high | Container image | config | Dockerfile | Image user should not be 'root' (DS-0002) | Add 'USER <non root user name>' line to the Dockerfile | yes |
| high | Source code | code | Dockerfile:6 | missing user (dockerfile.security.missing-user.missing-user) | By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'. | yes |
| high | Source code | code | app.py:20 | tainted sql string (python.django.security.injection.tainted-sql-string.tainted-sql-string) | Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries. | yes |
| high | Source code | code | app.py:21 | sqlalchemy execute raw query (python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query) | Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option. | yes |
| high | Source code | code | app.py:28 | subprocess injection (python.flask.security.injection.subprocess-injection.subprocess-injection) | Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, which allows them to download malware, scan sensitive data, or run any command they wish on the server. Do not let users choose the command to run. In general, prefer to use Python API versions of system commands. If you must use subprocess, use a dictionary to allowlist a set of commands. | yes |
| high | Source code | secret | config.py:5 | Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure. (github-pat) | Revoke and rotate the secret, then load it from an environment variable or a secrets manager instead. | yes |
| high | Infrastructure as code | config | infra/main.tf:8 | Security groups should not allow unrestricted ingress to SSH or RDP from any IP address. (AWS-0107) | Set a more restrictive CIDR range | yes |
| high | Kubernetes | config | k8s/deployment.yaml:14 | Default security context configured (KSV-0118) | To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context. | yes |
| high | Kubernetes | config | k8s/deployment.yaml:16 | Root file system is not read-only (KSV-0014) | Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'. | yes |
| high | Dependencies | dependency | requirements.txt | python-flask: Denial of Service via crafted JSON file (CVE-2018-1000656) | Upgrade flask to 0.12.3 or newer. | no |
| high | Dependencies | dependency | requirements.txt | python-flask: unexpected memory usage can lead to denial of service via crafted encoded JSON data (CVE-2019-1010083) | Upgrade flask to 1.0 or newer. | yes |
| high | Dependencies | dependency | requirements.txt | flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header (CVE-2023-30861) | Upgrade flask to 2.3.2, 2.2.5 or newer. | yes |
| high | Dependencies | dependency | requirements.txt | python-jinja2: str.format_map allows sandbox escape (CVE-2019-10906) | Upgrade jinja2 to 2.10.1 or newer. | yes |
| high | Dependencies | dependency | requirements.txt | python-requests: Redirect from HTTPS to HTTP does not remove Authorization header (CVE-2018-18074) | Upgrade requests to 2.20.0 or newer. | yes |
| medium | Source code | code | app.py:17 | sql injection db cursor execute (python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute) | User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`. | no |
| medium | Source code | code | app.py:33 | avoid_app_run_with_bad_host (python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host) | Running flask app with host 0.0.0.0 could expose the server publicly. | no |
| medium | Source code | code | k8s/deployment.yaml:18 | allow privilege escalation (yaml.kubernetes.security.allow-privilege-escalation.allow-privilege-escalation) | In Kubernetes, each pod runs in its own isolated environment with its own set of security policies. However, certain container images may contain `setuid` or `setgid` binaries that could allow an attacker to perform privilege escalation and gain access to sensitive resources. To mitigate this risk, it's recommended to add a `securityContext` to the container in the pod, with the parameter `allowPrivilegeEscalation` set to `false`. This will prevent the container from running any privileged processes and limit the impact of any potential attacks. By adding the `allowPrivilegeEscalation` parameter to your the `securityContext`, you can help to ensure that your containerized applications are more secure and less vulnerable to privilege escalation attacks. | no |
| medium | Source code | code | k8s/deployment.yaml:20 | privileged container (yaml.kubernetes.security.privileged-container.privileged-container) | Container or pod is running in privileged mode. This grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other security concerns. Remove the 'privileged' key to disable this capability. | no |
| medium | Dependencies | dependency | requirements.txt | python-jinja2: ReDoS vulnerability in the urlize filter (CVE-2020-28493) | Upgrade jinja2 to 2.11.3 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | jinja2: HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-22195) | Upgrade jinja2 to 3.1.3 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | jinja2: accepts keys containing non-attribute characters (CVE-2024-34064) | Upgrade jinja2 to 3.1.4 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | jinja2: Jinja has a sandbox breakout through indirect reference to format method (CVE-2024-56326) | Upgrade jinja2 to 3.1.5 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | jinja2: Jinja sandbox breakout through attr filter selecting format method (CVE-2025-27516) | Upgrade jinja2 to 3.1.6 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | python-requests: Unintended leak of Proxy-Authorization header (CVE-2023-32681) | Upgrade requests to 2.31.0 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | requests: subsequent requests to the same host ignore cert verification (CVE-2024-35195) | Upgrade requests to 2.32.0 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | requests: Requests vulnerable to .netrc credentials leak via malicious URLs (CVE-2024-47081) | Upgrade requests to 2.32.4 or newer. | no |
| medium | Dependencies | dependency | requirements.txt | requests: Requests: Security bypass due to predictable temporary file creation (CVE-2026-25645) | Upgrade requests to 2.33.0 or newer. | no |
| low | Infrastructure as code | config | infra/main.tf:2 | Missing description for security group. (AWS-0099) | Add descriptions for all security groups | no |
| low | Infrastructure as code | config | infra/main.tf:4 | Missing description for security group rule. (AWS-0124) | Add descriptions for all security groups rules | no |
| low | Kubernetes | config | k8s/deployment.yaml:3 | Workloads in the default namespace (KSV-0110) | Set 'metadata.namespace' to a non-default namespace. | no |
| low | Source code | code | k8s/deployment.yaml:14 | run as non root (yaml.kubernetes.security.run-as-non-root.run-as-non-root) | When running containers in Kubernetes, it's important to ensure that they  are properly secured to prevent privilege escalation attacks.  One potential vulnerability is when a container is allowed to run  applications as the root user, which could allow an attacker to gain  access to sensitive resources. To mitigate this risk, it's recommended to  add a `securityContext` to the container, with the parameter `runAsNonRoot`  set to `true`. This will ensure that the container runs as a non-root user,  limiting the damage that could be caused by any potential attacks. By  adding a `securityContext` to the container in your Kubernetes pod, you can  help to ensure that your containerized applications are more secure and  less vulnerable to privilege escalation attacks. | no |
| low | Dependencies | dependency | requirements.txt | flask: Flask: Information disclosure via improper caching of session data (CVE-2026-27205) | Upgrade flask to 3.1.3 or newer. | no |

## Waived (known and accepted)

- CVE-2018-1000656 in requirements.txt: Example waiver: the demo app does not accept JSON from users. Revisit after upgrading Flask. (expires 2026-12-31)
