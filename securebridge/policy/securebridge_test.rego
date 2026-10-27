# Unit tests for the policy. Run them with:  opa test policy/ -v
# A function whose name starts with "test_" is a test; it passes when its body is true.
package securebridge_test

import rego.v1

import data.securebridge

policy := {
	"block_at": {"secret": "low", "code": "high", "dependency": "high", "config": "high"},
	"waivers": [],
}

finding(category, severity) := {
	"category": category,
	"severity": severity,
	"rule_id": "R1",
	"file": "a.py",
	"line": 1,
	"layer": "source",
}

waiver(expires) := {
	"rule_id": "R1",
	"file": "a.py",
	"reason": "accepted for now",
	"expires": expires,
}

test_medium_code_finding_does_not_block if {
	not securebridge.decision.blocked with input as {
		"findings": [finding("code", "medium")],
		"policy": policy,
		"today": "2026-10-25",
	}
}

test_high_code_finding_blocks if {
	securebridge.decision.blocked with input as {
		"findings": [finding("code", "high")],
		"policy": policy,
		"today": "2026-10-25",
	}
}

test_any_secret_blocks_even_at_low_severity if {
	securebridge.decision.blocked with input as {
		"findings": [finding("secret", "low")],
		"policy": policy,
		"today": "2026-10-25",
	}
}

test_never_turns_blocking_off_for_a_kind_of_finding if {
	not securebridge.decision.blocked with input as {
		"findings": [finding("dependency", "critical")],
		"policy": {"block_at": {"dependency": "never"}, "waivers": []},
		"today": "2026-10-25",
	}
}

test_an_active_waiver_unblocks_and_is_counted if {
	d := securebridge.decision with input as {
		"findings": [finding("code", "high")],
		"policy": object.union(policy, {"waivers": [waiver("2026-12-31")]}),
		"today": "2026-10-25",
	}
	not d.blocked
	d.waived == 1
}

test_an_expired_waiver_no_longer_protects if {
	securebridge.decision.blocked with input as {
		"findings": [finding("code", "high")],
		"policy": object.union(policy, {"waivers": [waiver("2026-01-01")]}),
		"today": "2026-10-25",
	}
}

test_a_waiver_for_another_file_does_not_apply if {
	other := {"rule_id": "R1", "file": "b.py", "reason": "x", "expires": "2026-12-31"}
	securebridge.decision.blocked with input as {
		"findings": [finding("code", "high")],
		"policy": object.union(policy, {"waivers": [other]}),
		"today": "2026-10-25",
	}
}

test_missing_settings_fall_back_to_blocking_at_high if {
	securebridge.decision.blocked with input as {
		"findings": [finding("code", "high")],
		"policy": {},
		"today": "2026-10-25",
	}
	not securebridge.decision.blocked with input as {
		"findings": [finding("code", "medium")],
		"policy": {},
		"today": "2026-10-25",
	}
}

test_an_unknown_severity_is_reported_as_invalid_not_silently_ignored if {
	d := securebridge.decision with input as {
		"findings": [finding("code", "banana")],
		"policy": policy,
		"today": "2026-10-25",
	}
	d.invalid == 1
}

test_counts_match_for_a_mixed_batch if {
	d := securebridge.decision with input as {
		"findings": [
			finding("code", "high"),
			finding("code", "medium"),
			finding("secret", "high"),
		],
		"policy": policy,
		"today": "2026-10-25",
	}
	d.blocked
	d.blocking == 2
}
