"""The command line: ties runner, policy and report together.

LESSON 10 (exit codes): a pipeline cannot read a report. It can only look at one
number the program returns when it finishes: 0 means success, anything else means
failure. That single number is how "block the deployment" actually happens.
  0 = passed
  1 = blocked by policy (the pipeline should stop)
  2 = could not do the job (for example, no scanner could run)
"""
from __future__ import annotations

import argparse
import os
import sys

from . import report
from .layers import classify, first_defective, summarize
from .policy import evaluate, load_policy
from .runner import deduplicate, run_demo, run_real

TOOLS = ["gitleaks", "semgrep", "trivy"]
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="bridge", description="SecureBridge phase 1")
    parser.add_argument("command", choices=["scan"])
    parser.add_argument("path", help="folder to scan, for example sample-app")
    parser.add_argument("--demo", action="store_true",
                        help="use saved sample scanner outputs instead of running the tools")
    parser.add_argument("--policy", default=os.path.join(HERE, "policy.json"))
    parser.add_argument("--out", default="out", help="folder for the reports")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: {args.path} is not a folder", file=sys.stderr)
        return 2

    # 1. Run every scanner (or load sample outputs) and collect the findings.
    runs = []
    for tool in TOOLS:
        if args.demo:
            runs.append(run_demo(tool, os.path.join(HERE, "fixtures"), root))
        else:
            runs.append(run_real(tool, root))

    if not any(r.status in ("ok", "demo") for r in runs):
        print("error: no scanner could run, so there is nothing to report.", file=sys.stderr)
        for r in runs:
            print(f"  {r.name}: {r.status} - {r.detail}", file=sys.stderr)
        print("Install the tools (see README) or try --demo.", file=sys.stderr)
        return 2

    # 2. Merge everything into one list and remove duplicates.
    all_findings = [f for r in runs for f in r.findings]
    findings, dropped = deduplicate(all_findings)

    # 2b. Decide which DevOps layer each finding belongs to.
    for finding in findings:
        finding.layer = classify(finding, root)

    # 3. Ask the policy whether this is acceptable.
    decision = evaluate(findings, load_policy(args.policy))

    # 4. Write the three reports.
    os.makedirs(args.out, exist_ok=True)
    outputs = {
        "report.md": report.to_markdown(runs, findings, decision, dropped),
        "report.json": report.to_json(runs, findings, decision, dropped),
        "report.sarif": report.to_sarif(findings),
    }
    for name, text in outputs.items():
        with open(os.path.join(args.out, name), "w") as handle:
            handle.write(text)

    # 5. Tell the human, then tell the pipeline (via the exit code).
    for r in runs:
        print(f"{r.name:9} {r.status:8} {r.detail}")
    print(f"\n{len(findings)} finding(s), {len(decision.blocking)} blocking, "
          f"{len(decision.waived)} waived, {dropped} duplicate(s) merged")
    print("\nLayers, from code to production:")
    rows = summarize(runs, findings, decision)
    for number, row in enumerate(rows, start=1):
        extra = f" ({row['findings']} finding(s))" if row["findings"] else ""
        print(f"  {number}. {row['name']:<24} {row['status']}{extra}")
    broken = first_defective(rows)
    if broken:
        print(f"Start fixing at: {broken['name']}")
    print(f"\nreports written to {args.out}/")
    print("VERDICT:", "BLOCKED" if decision.blocked else "PASSED")
    return 1 if decision.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
