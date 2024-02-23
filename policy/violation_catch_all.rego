package catch_all

import data.common

# violation_catch_all_allow is a rule that identifies Google Compute Firewall rules
# that are not delete or no-op actions and have an 'allow' action in their configuration.
# This rule is part of a catch-all policy aimed at ensuring all firewall rules are audited and tracked.
# It is utilized by an external process for validation purposes, ensuring comprehensive audit coverage.
violation_catch_all_allow[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action == "delete"
	action == "no-op"

	common.rule_action(resource.change.after.allow) == "ALLOW"
	result := common.template_result(
		"CATCH_ALL",
		resource,
		"Catch-all rule used for tracking to identify any rule that is not being audited",
	)
}