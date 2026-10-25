# SecureBridge, phase 1

A small engine that runs several security scanners, translates their different outputs
into one common format, applies a policy, and answers **passed** or **blocked**.
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

- Semgrep: `pip install semgrep`
- Gitleaks and Trivy: `brew install gitleaks trivy` (macOS/Linux), or follow each
  project's official install page (Windows, Docker and other options are listed there).

```
python3 -m bridge scan sample-app
```

Missing tools are reported as `skipped`, never as a clean result. Exit code: `0` passed,
`1` blocked, `2` could not run.

## Layout

```
sample-app/   intentionally vulnerable app (never deploy it)
fixtures/     hand-written sample scanner outputs for --demo (see its README)
bridge/       models, adapters, runner, policy, report, cli
policy.json   the blocking rules and waivers
tests/        16 tests
LESSONS.md    the guided tour
```
