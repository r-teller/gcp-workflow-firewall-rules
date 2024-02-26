# Purpose: Identifies critical risk changes in GCP firewall rules that allow ingress traffic on sensitive TCP and/or UDP
# ports. This rule aims to highlight configurations that could expose sensitive or essential services to unauthorized
# external access, marking these changes as critical risks.
#
# Functionality: The rule processes each entry in `input.resource_changes`, specifically targeting "google_compute_firewall"
# resources. It filters for actions that are neither no-ops nor deletions, focusing on creations or modifications. The
# critical check involves determining if the proposed firewall rule allows traffic on ports considered sensitive due to
# their common use in managing, accessing, or exploiting networked services. If such a condition is met, the rule generates
# a warning that includes the firewall rule's name, the action being performed, and a detailed message explaining the
# critical risk associated with allowing traffic on sensitive ports.
#
# Context: Proper configuration of firewall rules is paramount in safeguarding cloud infrastructure. This rule is crucial
# for early detection of rule changes that significantly increase the risk profile by potentially opening up sensitive
# network ports to external access. It serves as a proactive measure to ensure that firewall configurations adhere to
# stringent security standards, preventing inadvertent exposure of critical services.
#
# Note: This rule is part of a comprehensive security framework designed to maintain the integrity and security of the cloud
# environment. It works in conjunction with other policies to provide a multi-layered defense against various security
# threats, emphasizing the importance of strict firewall rule management.

package critical_upsert_allow_ingress

import data.common

warn_contains_sensitive_ports[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"
	action != "delete"

	upper(resource.change.after.direction) == "INGRESS"
	upper(common.rule_action(resource.change.after.allow[_])) == "ALLOW"

	common.contains_sensitive_ports(resource.change.after)

	result := common.template_result(
		"CRITICAL",
		resource,
		sprintf("Firewall Rule '%s' will be %s, and this change is considered high risk because (%s).", [
			resource.change.after.name, common.action_description(action),
			"allows one or more sensitive TCP and/or UDP ports and/or port-ranges",
		]),
	)
}
