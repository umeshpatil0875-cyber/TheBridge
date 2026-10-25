# Phase 1 lessons: learn DevSecOps by reading the code

Read this top to bottom with the code open next to it. Each lesson names the file
where the idea lives. Nothing here assumes you know the terms already.

## Step 0: see it work (5 minutes)

```
python3 -m bridge scan sample-app --demo
```

(On Windows, use `python` instead of `python3`.) You should see a table of results
and the line `VERDICT: BLOCKED`. Open `out/report.md` and read it. Everything below
explains how that report came to exist.

---

## The story in one paragraph

`sample-app/` is a tiny web app with security mistakes planted on purpose. Three
**scanners** (programs that inspect code for problems) each look for a different kind
of mistake. They all report in different formats, so the **bridge** translates every
report into one common shape, removes duplicates, asks a **policy** whether the result
is acceptable, and then writes reports and answers "pass" or "blocked".

---

## Lesson 0: what is a scanner, and why three?

A scanner is a program that reads your project and flags known mistakes, a bit like a
spell-checker for security. No single scanner covers everything, so teams run several:

| Scanner | Looks for | Planted example in `sample-app/` |
| --- | --- | --- |
| **Gitleaks** | Secrets (passwords, API tokens) left in code | a fake token in `config.py` |
| **Semgrep** | Risky code patterns (called SAST) | SQL injection in `app.py` line 20 |
| **Trivy** | Known-vulnerable libraries and bad infrastructure settings | old libraries in `requirements.txt`, root user in `Dockerfile` |

Why each matters:

- **Secret in code:** anyone who can read the code (or its history) can use the secret.
  Fix by revoking it and loading secrets from outside the code.
- **SQL injection:** an attacker types database commands into a web form and your app
  runs them. Fix by passing user input as parameters, never gluing it into the query.
- **Vulnerable library (CVE):** a CVE is a numbered public record of a known flaw, for
  example `CVE-2018-18074`. You did not write the bug, but you ship it. Fix by upgrading.
- **Running as root in a container:** if an attacker breaks into the app, they get
  maximum power inside the container. Fix by adding a non-root `USER`.

## Lesson 1: one common shape (`bridge/models.py`)

Gitleaks calls the file `File`, Semgrep calls it `path`, Trivy calls it `Target`.
You cannot rank or compare things that are described differently. So we define one
`Finding` shape and convert everything into it. Every later step (policy, reports,
the future dashboard) only knows `Finding`.

> Analogy: three people measure in inches, centimetres and hand-spans. Before comparing,
> everyone converts to centimetres.

**Try it:** open `models.py` and find the five fields that every finding must have.

## Lesson 2: adapters are the "bridge" (`bridge/adapters.py`)

One small function per scanner: raw output in, `Finding` list out. This is the whole
trick behind connecting many tools. To support a fourth scanner later, you write one
more function here and change nothing else.

**Try it:** read `parse_gitleaks`. It is about 15 lines. Notice it never touches policy
or reports.

## Lesson 3: severity is a decision, not a fact (`adapters.py`)

Trivy says `HIGH`, Semgrep says `ERROR`, Gitleaks says nothing. We chose a mapping:
leaked secrets count as `high`, Semgrep `ERROR` becomes `high`, `WARNING` becomes
`medium`. These choices are visible in plain tables at the top of each adapter,
because teams will argue about them and need to change them.

**Try it:** change Semgrep `WARNING` to map to `high`, run the demo, and watch the
`debug enabled` finding start blocking. Undo it afterwards.

## Lesson 4: duplicates destroy trust (`models.py`, `runner.py`)

If two tools report the same leaked password, the team sees two alarms for one problem.
Teams that see noisy reports stop reading them. `deduplicate` merges findings that share
a `dedupe_key` and keeps the more severe one. This is a small taste of what commercial
ASPM tools do at large scale.

## Lesson 5: never copy a secret into a report (`adapters.py`)

Gitleaks output includes the leaked value itself. Our adapter deliberately drops it.
Reports get pasted into tickets and uploaded to dashboards; copying the secret would
create a new leak. A test (`test_bridge.py`) searches every report file for the token
and fails if it appears.

## Lesson 6: fail soft, but never fake a clean result (`runner.py`)

If a scanner is missing or crashes, the bridge keeps going with the others, but it
records a status (`ok`, `skipped`, `failed`, `demo`) and prints a warning in the report.
If no scanner runs at all, it refuses to produce a report (exit code 2) instead of
saying "all clear". A security tool that silently skips checks is dangerous, because
people trust the green tick.

## Lesson 7: policy is data (`policy.json`, `bridge/policy.py`)

The rules live in a JSON file:

```
"block_at": { "secret": "low", "code": "high", "dependency": "high", "config": "high" }
```

Read it as: any secret blocks, but code and library problems only block at `high` or
above. Security people can change the rules without reading Python. Large companies
do the same with a policy language (OPA, which you will meet in phase 2). **Policy as
code** means the rules are written down, versioned and reviewed, not kept in someone's head.

**Try it:** change `"code": "high"` to `"code": "medium"` and re-run. The `debug enabled`
finding now blocks.

## Lesson 8: waivers need an expiry date (`policy.json`, `policy.py`)

Sometimes you cannot fix something today. A **waiver** records "we accept this for
now, here is why, and we will revisit by this date". Without expiry dates, waivers
pile up and become permanent holes. In this project an expired waiver simply stops
working, and the report lists it so someone notices.

**Try it:** the example waiver expires on 2026-12-31. Change it to a past date and
watch `CVE-2018-1000656` start blocking again, with an "Expired waivers" section in
the report.

## Lesson 9: SARIF, the shared language (`bridge/report.py`)

SARIF is an open standard format for scanner results. We export one `report.sarif`
file. Platforms like GitHub can display SARIF directly in their Security tab, so
writing it once gives you a polished viewer for free (that is phase 3 of the plan).
We produce three reports for three audiences: `report.md` for people, `report.json`
for programs (a dashboard later), `report.sarif` for security platforms.

## Lesson 10: exit codes are how pipelines make decisions (`bridge/cli.py`)

A CI/CD pipeline (the automatic assembly line that builds and ships your code) cannot
read a report. It only checks one number when a program ends: `0` means success,
anything else means failure. Our bridge returns:

- `0` passed
- `1` blocked by policy, so the pipeline stops and nothing ships
- `2` could not do its job

Check it yourself: run the scan, then type `echo $?` (macOS/Linux) or `echo %errorlevel%`
(Windows Command Prompt). In phase 3, GitHub Actions will use exactly this number to stop
a bad pull request.

## Lesson 11: tests protect the trust (`tests/test_bridge.py`)

```
python3 -m unittest discover -s tests -v
```

The tests pin down the behaviours that matter most: severity mapping, dedupe, policy,
waivers, "secret never leaks", and "no scanners means no fake pass". There is also a test
that every sample finding points at a real file and line in `sample-app/`, so the
demo cannot drift away from the app it claims to scan.

---

## Running the real scanners

Demo mode reads saved sample outputs from `fixtures/`. Those samples were written by hand
in each tool's output layout, so the real tools may report more, fewer or differently
worded results.

To use the real thing, install the three tools (see README), then:

```
python3 -m bridge scan sample-app
```

The engine runs each installed tool, loads its JSON output through the same adapters,
and the rest is identical. A tool that is not installed is reported as `skipped`.

**Honest caveat:** the exact command-line flags in `bridge/runner.py` were checked for
plumbing (a stand-in script played each tool) but not against the real programs, and
scanner flags change between versions. If a tool reports `failed`, read the detail
line in the report, compare with that tool's `--help`, and adjust `_command()`. That is
a normal part of this work.

## Small glossary for this phase

- **Pipeline (CI/CD):** automatic build, test and deploy steps that run when code changes.
- **Scanner:** a program that inspects code or config for known problems.
- **SAST:** scanning source code without running it.
- **CVE:** a public, numbered record of a known vulnerability.
- **SARIF:** a standard file format for scanner results.
- **Policy:** the rules that decide what is acceptable.
- **Waiver:** a documented, time-limited exception to a rule.
- **Exit code:** the number a program returns to say whether it succeeded.
- **Dedupe:** merging reports of the same problem.

## What comes next (phase 2)

Today the bridge runs on your laptop and the policy is a JSON file. Next:

1. Replace the JSON policy with OPA/Rego rules (real policy as code).
2. Put the bridge inside a GitHub Actions workflow so every pull request is scanned.
3. Store findings in a database behind a small API, which becomes the SaaS backend.
