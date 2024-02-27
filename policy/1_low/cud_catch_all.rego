# Purpose: Identifies and warns about low-risk actions on Google Compute Firewall rules, including modifications, creations,
# and deletions, except no-ops.
#
# Functionality: Iterates over `input.resource_changes`, focusing on "google_compute_firewall". Examines the actions array
# to determine the operation type (create, modify, delete), excluding "no-op" actions. Constructs a warning for actions
# considered low risk, using a common template for consistency in messaging and severity classification.
#
# Context: This rule is integral to a policy framework aimed at securing cloud infrastructure. By flagging low-risk actions,
# it enables prioritized review and intervention, balancing security alerting with operational noise minimization.
#
# Note: While categorizing certain changes as low risk, this rule is part of a layered security approach. Other policies may
# override this classification based on stricter criteria or additional context, ensuring an adaptive security posture.

package low_cud_catch_all

import data.common

warn_catch_all[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "no-op"


	result := common.template_result(
		"LOW",
		resource,
		sprintf("Firewall Rule '%s' will be %s, and this change is considered low risk other policies may override this risk rating.", [common.select_resource_change(resource.change).name, common.action_description(action)]),
	)
}