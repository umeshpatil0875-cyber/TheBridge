# SecureBridge, phase 1

A small engine that runs several security scanners, translates their different outputs
into one common format, sorts every finding into a DevOps **layer** (source code,
dependencies, pipeline, container, infrastructure, Kubernetes, running system), applies a
policy, and answers **passed** or **blocked**, naming which layers are defective.
It is the core of a future DevSecOps SaaS. Start with `LESSONS.md` if the terms are new.

## Try it now (no installs, Python 3.9+ only)

```
python3 -m bridge scan sample-app --demo      # on Windows: python -m bridge ...
python3 -m unittest discover -s tests -v      # run the tests
```

Reports are written to `out/`: `report.md`, `report.json`, `report.sarif`.
A ready-made copy is in `example-output/`.

## Use the real scanners

Install these on your machine, then drop `--demo`:

- Semgrep and zizmor: `pip install semgrep zizmor`
- Gitleaks and Trivy: `brew install gitleaks trivy` (macOS/Linux), or follow each
  project's official install page (Windows, Docker and other options are listed there).

```
python3 -m bridge scan sample-app
```

Missing tools are reported as `skipped`, never as a clean result. Exit code: `0` passed,
`1` blocked, `2` could not run.

## Run it on GitHub (phase 2a)

1. Create a new, empty repository on GitHub. A public one is simplest, because uploading
   to the Security tab is free there.
2. Make **this folder** the repository root, so that `.github/workflows/` sits at the top:

   ```
   git init -b main
   git add .
   git commit -m "SecureBridge phase 2a"
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```

3. Open the **Actions** tab and watch "SecureBridge" run. The `scan` job is expected to turn
   **red**: the sample app is vulnerable on purpose, so the verdict is BLOCKED.
4. Open the run and read the layer table in the summary. If you used a public repo, also
   open **Security > Code scanning**.
5. Optional but important: Settings > Branches (or Rules) > protect `main` and require the
   `scan` check, so a blocked pull request cannot be merged.

If GitHub refuses the push because it spotted a "secret", that is the planted fake token
in `sample-app/config.py` being caught. It is not real and works nowhere.
Read Lesson 14 in `LESSONS.md` for what each part of the workflow does and what could
not be tested.

## Layout

```
sample-app/   intentionally vulnerable app (never deploy it)
fixtures/     hand-written sample scanner outputs for --demo (see its README)
bridge/       models, adapters, runner, layers, policy, opa, report, cli, store, server, upload
policy.json   the blocking settings and waivers
policy/       the same rules as Rego (OPA) + Rego unit tests
scripts/      install-opa.sh (used by the workflow)
tests/        104 tests
.github/      the GitHub Actions workflow (phase 2a)
LESSONS.md    the guided tour
```

## Policy as code (OPA, shadow mode)

```
brew install opa            # or: bash scripts/install-opa.sh
opa check policy/           # syntax check
opa test policy/ -v         # Rego unit tests
python -m bridge scan sample-app --policy-engine shadow   # compare only
python -m bridge scan sample-app --policy-engine opa      # OPA decides, fails closed
```

`sample-app-fixed/` is the repaired copy of `sample-app/` (scan it to see PASSED).

Shadow mode: Python still decides the exit code; OPA's answer is shown next to it
as agree / disagree / skipped / error. See Lesson 19 in LESSONS.md.

## Phase 3: history and an API

```
python -m bridge.server create-project my-team          # prints a token once
python -m bridge.server serve --port 8080               # the API
SECUREBRIDGE_TOKEN=sb_... python -m bridge scan sample-app --upload-url http://127.0.0.1:8080
```

Endpoints: `GET /healthz`, `POST /api/v1/scans`, `GET /api/v1/scans`, `GET /api/v1/scans/<id>`,
`GET /api/v1/trend`. Login with `Authorization: Bearer <token>`. See Lesson 21. This is a
learning version: plain HTTP, SQLite, one process.

## Dashboard

With the API running, open `http://127.0.0.1:8080/dashboard`, paste your project token and press Connect.
Charts: findings over time, severity mix, new vs fixed, findings by layer and by scanner, plus tables.
One self-contained file (`bridge/dashboard.html`), light and dark mode, no outside libraries. See Lesson 25.
