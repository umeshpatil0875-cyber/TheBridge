# SecureBridge policy, written in Rego (the language of Open Policy Agent, "OPA").
#
# It makes the same decision as bridge/policy.py: which findings block the pipeline.
# Read LESSONS.md, Lesson 19, for a line-by-line explanation.
#
# INPUT (what the bridge sends to OPA):
#   input.findings  a list of findings (each has category, severity, rule_id, file, ...)
#   input.policy    the contents of policy.json (block_at thresholds and waivers)
#   input.today     today's date as "YYYY-MM-DD"
#
# OUTPUT: data.securebridge.decision
package securebridge

import rego.v1

# Severities from least to most serious. The position in the list is the rank,
# exactly like SEVERITIES in bridge/models.py. A test checks the two lists match.
severities := ["info", "low", "medium", "high", "critical"]

rank(severity) := i if {
	some i, s in severities
	s == severity
}

# Settings, with safe fallbacks if policy.json leaves something out.
block_at := object.get(input.policy, "block_at", {})

waivers := object.get(input.policy, "waivers", [])

default_limit := object.get(block_at, "default", "high")

# The lowest severity that blocks for this kind of finding. "never" turns blocking off.
limit(finding) := object.get(block_at, finding.category, default_limit)

# Does this finding reach the blocking threshold?
applies(finding) if {
	limit(finding) != "never"
	rank(finding.severity) >= rank(limit(finding))
}

# A waiver covers a finding when it names no file, or names the finding's file.
covers(waiver, finding) if {
	object.get(waiver, "file", null) == null
}

covers(waiver, finding) if {
	waiver.file == finding.file
}

# Positions (in input.findings) of findings excused by a waiver that has not expired.
# Dates in YYYY-MM-DD form sort correctly as plain text, so >= compares them.
waived_idx contains i if {
	some i, finding in input.findings
	applies(finding)
	some waiver in waivers
	waiver.rule_id == finding.rule_id
	covers(waiver, finding)
	waiver.expires >= input.today
}

# Positions of findings that reach the threshold and are not waived: these block.
blocking_idx contains i if {
	some i, finding in input.findings
	applies(finding)
	not waived_idx[i]
}

# In Rego, "undefined" is not the same as "false", and an undefined rule silently
# lets things through. A finding whose severity is not in the list above would make
# rank() undefined and so never block. We count those, so bad data is visible.
invalid_idx contains i if {
	some i, finding in input.findings
	not rank(finding.severity)
}

decision := {
	"blocked": count(blocking_idx) > 0,
	"blocking": count(blocking_idx),
	"waived": count(waived_idx),
	"invalid": count(invalid_idx),
	"blocking_indexes": blocking_idx,
}
