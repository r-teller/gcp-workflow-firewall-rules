# Purpose: Blocks configurations of Google Compute Firewall rules that are deemed unsafe: those with non-supported logging
# configurations (`deny_incorrect_logging`) and rules that allow ingress from all to all (`deny_allow_all_to_all`), marking
# these changes as critical risks that should not be pushed to production.
#
# Functionality: This file contains two primary rules:
# 1. `deny_incorrect_logging`: Iterates over `input.resource_changes`, targeting "google_compute_firewall" resources. It
#    checks for changes (excluding no-ops and deletions) that involve logging configurations not adhering to best practices.
#    If such a configuration is detected, the rule blocks the change, providing a detailed message about the issue.
# 2. `deny_allow_all_to_all`: Similar to the first, this rule scans for firewall rules that indiscriminately allow all ingress
#    traffic, a configuration that significantly increases security risks. It blocks such changes, issuing a warning.
#
# Context: In the realm of cloud infrastructure, maintaining strict control over firewall configurations is crucial for
# security. These rules enforce stringent checks to prevent potentially harmful changes from being implemented, ensuring
# that only secure, well-configured firewall rules are allowed.
#
# Note: These blocking rules are part of a layered security approach, designed to catch and mitigate critical risks before
# they can impact the cloud environment. They serve as a final checkpoint in a series of policies aimed at upholding high
# security standards.

package blocking_upsert_catch_all

import data.common

deny_incorrect_logging[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"
	action != "delete"

	log_config := resource.change.after.log_config
	not common.is_log_config_set(log_config)

	result := common.template_result(
		"BLOCKING",
		resource,
		sprintf("Firewall Rule '%s' will be '%s', and this change contains non-support logging configation and SHOULD NOT be pushed.", [resource.change.after.name, common.action_description(action)]),
	)
}

deny_allow_all_to_all[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"
	action != "delete"

	common.is_any_sources(resource.change.after)
	common.is_any_targets(resource.change.after)

	result := common.template_result(
		"BLOCKING",
		resource,
		sprintf("Firewall Rule '%s' will be '%s', and this change contains an allow ingress from all to all configation and SHOULD NOT be pushed.", [resource.change.after.name, common.action_description(action)]),
	)
}

deny_allow_priority_le_1000[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"
	action != "delete"
	
	upper(common.rule_action(resource.change.after.allow[_])) == "ALLOW"
	
	resource.change.after.priority < 1000

	result := common.template_result(
		"BLOCKING",
		resource,
		sprintf("Firewall Rule '%s' will be '%s', and this change contains a priority less-than 1000 and SHOULD NOT be pushed", [resource.change.after.name, common.action_description(action)]),
	)
}