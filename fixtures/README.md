# Demo fixtures

These three files are **hand-written samples** that follow the native JSON output
layout of Gitleaks, Semgrep, Trivy and zizmor. They were NOT produced by running the real
tools. They exist so you can run the bridge in `--demo` mode before installing
anything, and so the tests have stable input.

`zizmor.json` follows the JSON layout described in zizmor's documentation (a flat list,
severity under `determinations`, zero-based line numbers). Its rule names are real zizmor
audits, but the wording, severities and confidence levels were written by hand and may
differ from the real tool.

The findings point at the flaws planted in `../sample-app` (including the Kubernetes and
Terraform entries in `trivy.json`, whose rule ids and wording are written from memory
of Trivy's style and may differ from the real tool). Real scanners may report
more, fewer, or differently worded findings. When you run in normal mode with the real
tools installed, you will see their actual output.

`zap.json` follows OWASP ZAP's traditional JSON report layout (`site` -> `alerts` -> `instances`, `riskcode` 0-3). It is hand-written from memory of that layout and describes the weak mode of `../runtime-target`. It is only loaded in demo mode together with `--target-url`.
