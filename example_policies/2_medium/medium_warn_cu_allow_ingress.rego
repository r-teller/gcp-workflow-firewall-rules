# Purpose: Enhances GCP security by identifying firewall rules allowing ingress from non-trusted CIDR ranges, marking such
# changes as medium risk.
#
# Functionality: Processes `input.resource_changes`, focusing on "google_compute_firewall". Filters actions, excluding no-ops
# and deletions, focusing on creations or modifications. Checks if traffic direction is "INGRESS" and action is "ALLOW". Uses
# `common.is_trusted_cidrs_source` to evaluate if source CIDRs are trusted. Generates a warning for ingress from non-trusted
# sources, including the firewall rule name, action, and a message about the medium risk.
#
# Context: Managing access via firewall rules is crucial for cloud security. This rule helps identify potential exposures to
# untrusted networks, prompting review and possible revision to align with security policies.
#
# Note: This rule is part of a set aimed at robust security in GCP environments, complementing others for a comprehensive
# approach to cloud security.

package medium_warn_cu_allow_ingress

import data.common

warn_non_trusted_sources[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"
	action != "delete"

	upper(resource.change.after.direction) == "INGRESS"
	upper(common.rule_action(resource.change.after.allow[_])) == "ALLOW"

	not common.is_trusted_cidrs_source(resource.change.after)

	result := common.template_result(
		"MEDIUM",
		resource,
		sprintf("Firewall Rule '%s' will be %s, and this change is considered medium risk because (%s).", [resource.change.after.name, common.action_description(action), "non-trusted source ranges"]),
	)
}
