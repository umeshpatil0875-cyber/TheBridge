# Demo fixtures

These three files are **hand-written samples** that follow the native JSON output
layout of Gitleaks, Semgrep and Trivy. They were NOT produced by running the real
tools. They exist so you can run the bridge in `--demo` mode before installing
anything, and so the tests have stable input.

The findings point at the flaws planted in `../sample-app` (including the Kubernetes and
Terraform entries in `trivy.json`, whose rule ids and wording are written from memory
of Trivy's style and may differ from the real tool). Real scanners may report
more, fewer, or differently worded findings. When you run in normal mode with the real
tools installed, you will see their actual output.
