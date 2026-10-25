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
bridge/       models, adapters, runner, layers, policy, report, cli
policy.json   the blocking rules and waivers
tests/        51 tests
.github/      the GitHub Actions workflow (phase 2a)
LESSONS.md    the guided tour
```
