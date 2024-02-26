# Purpose: Identifies high-risk firewall rule changes in GCP that allow all TCP and/or UDP ports for ingress traffic,
# marking these changes as high risk due to their broad network exposure potential.
#
# Functionality: Iterates over `input.resource_changes`, specifically targeting "google_compute_firewall" resources. It
# evaluates actions to exclude no-ops and deletions, focusing on creations or modifications. The rule checks if the
# firewall rule's direction is set to "INGRESS" and if it allows traffic on all TCP and/or UDP ports. A warning is generated
# for such rules, including the rule's name, the action being performed, and a message highlighting the high-risk nature of
# allowing all ports.
#
# Context: Open firewall rules pose a significant security risk by potentially exposing cloud resources to malicious
# traffic. This rule aids in the early detection of overly permissive rules, encouraging a prompt review and tightening of
# firewall configurations to adhere to the principle of least privilege.
#
# Note: This rule is a critical component of a comprehensive security strategy aimed at minimizing the attack surface within
# GCP environments. It complements other policies by focusing on high-risk configurations that require immediate attention.

package high_upsert_allow_ingress

import data.common

warn_all_tcp_or_udp_ports[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"
	action != "delete"

	upper(resource.change.after.direction) == "INGRESS"
	upper(common.rule_action(resource.change.after.allow[_])) == "ALLOW"

	common.is_any_tcp_or_udp(resource.change.after)

	result := common.template_result(
		"HIGH",
		resource,
		sprintf("Firewall Rule '%s' will be %s, and this change is considered high risk because (%s).", [resource.change.after.name, common.action_description(action), "allows all ports on TCP and/or UDP"]),
	)
}
