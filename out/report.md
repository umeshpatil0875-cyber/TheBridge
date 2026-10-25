# SecureBridge report

**Verdict: BLOCKED** (12 blocking, 1 waived)

## Scanners

| Scanner | Status | Detail |
| --- | --- | --- |
| gitleaks | ok | 1 finding(s) |
| semgrep | ok | 11 finding(s) |
| trivy | ok | 19 finding(s) |

## Findings by severity

| Severity | Count |
| --- | --- |
| critical | 2 |
| high | 11 |
| medium | 11 |
| low | 1 |

6 duplicate finding(s) from different tools were merged.

## All findings

| Severity | Kind | Where | What | Fix | Blocks? |
| --- | --- | --- | --- | --- | --- |
| critical | dependency | requirements.txt | PyYAML: incomplete fix for CVE-2020-1747 (CVE-2020-14343) | Upgrade pyyaml to 5.4 or newer. | yes |
| critical | dependency | requirements.txt | PyYAML: arbitrary command execution through python/object/new when FullLoader is used (CVE-2020-1747) | Upgrade pyyaml to 5.3.1 or newer. | yes |
| high | config | Dockerfile | Image user should not be 'root' (DS-0002) | Add 'USER <non root user name>' line to the Dockerfile | yes |
| high | code | Dockerfile:6 | missing user (dockerfile.security.missing-user.missing-user) | By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'. | yes |
| high | code | app.py:20 | tainted sql string (python.django.security.injection.tainted-sql-string.tainted-sql-string) | Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries. | yes |
| high | code | app.py:21 | sqlalchemy execute raw query (python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query) | Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option. | yes |
| high | code | app.py:28 | subprocess injection (python.flask.security.injection.subprocess-injection.subprocess-injection) | Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, which allows them to download malware, scan sensitive data, or run any command they wish on the server. Do not let users choose the command to run. In general, prefer to use Python API versions of system commands. If you must use subprocess, use a dictionary to allowlist a set of commands. | yes |
| high | secret | config.py:5 | Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure. (github-pat) | Revoke and rotate the secret, then load it from an environment variable or a secrets manager instead. | yes |
| high | dependency | requirements.txt | python-flask: Denial of Service via crafted JSON file (CVE-2018-1000656) | Upgrade flask to 0.12.3 or newer. | no |
| high | dependency | requirements.txt | python-flask: unexpected memory usage can lead to denial of service via crafted encoded JSON data (CVE-2019-1010083) | Upgrade flask to 1.0 or newer. | yes |
| high | dependency | requirements.txt | flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header (CVE-2023-30861) | Upgrade flask to 2.3.2, 2.2.5 or newer. | yes |
| high | dependency | requirements.txt | python-jinja2: str.format_map allows sandbox escape (CVE-2019-10906) | Upgrade jinja2 to 2.10.1 or newer. | yes |
| high | dependency | requirements.txt | python-requests: Redirect from HTTPS to HTTP does not remove Authorization header (CVE-2018-18074) | Upgrade requests to 2.20.0 or newer. | yes |
| medium | code | app.py:17 | sql injection db cursor execute (python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute) | User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`. | no |
| medium | code | app.py:33 | avoid_app_run_with_bad_host (python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host) | Running flask app with host 0.0.0.0 could expose the server publicly. | no |
| medium | dependency | requirements.txt | python-jinja2: ReDoS vulnerability in the urlize filter (CVE-2020-28493) | Upgrade jinja2 to 2.11.3 or newer. | no |
| medium | dependency | requirements.txt | jinja2: HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-22195) | Upgrade jinja2 to 3.1.3 or newer. | no |
| medium | dependency | requirements.txt | jinja2: accepts keys containing non-attribute characters (CVE-2024-34064) | Upgrade jinja2 to 3.1.4 or newer. | no |
| medium | dependency | requirements.txt | jinja2: Jinja has a sandbox breakout through indirect reference to format method (CVE-2024-56326) | Upgrade jinja2 to 3.1.5 or newer. | no |
| medium | dependency | requirements.txt | jinja2: Jinja sandbox breakout through attr filter selecting format method (CVE-2025-27516) | Upgrade jinja2 to 3.1.6 or newer. | no |
| medium | dependency | requirements.txt | python-requests: Unintended leak of Proxy-Authorization header (CVE-2023-32681) | Upgrade requests to 2.31.0 or newer. | no |
| medium | dependency | requirements.txt | requests: subsequent requests to the same host ignore cert verification (CVE-2024-35195) | Upgrade requests to 2.32.0 or newer. | no |
| medium | dependency | requirements.txt | requests: Requests vulnerable to .netrc credentials leak via malicious URLs (CVE-2024-47081) | Upgrade requests to 2.32.4 or newer. | no |
| medium | dependency | requirements.txt | requests: Requests: Security bypass due to predictable temporary file creation (CVE-2026-25645) | Upgrade requests to 2.33.0 or newer. | no |
| low | dependency | requirements.txt | flask: Flask: Information disclosure via improper caching of session data (CVE-2026-27205) | Upgrade flask to 3.1.3 or newer. | no |

## Waived (known and accepted)

- CVE-2018-1000656 in requirements.txt: Example waiver: the demo app does not accept JSON from users. Revisit after upgrading Flask. (expires 2026-12-31)
