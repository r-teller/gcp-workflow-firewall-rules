package upsert_allowed_sources

import data.common

# import rego.v1

# import future.keywords.if
# import future.keywords.in

# default v := false

# test {
# 	"udp" == input.resource_changes[_].change.after.allow[_].protocol
# } else {
# 	"tcp" == input.resource_changes[_].change.after.allow[_].protocol
# } else := false

# WARN if a firewall rule allows traffic from trusted source ranges
warn_ingress_allow[result] {
	resource := input.resource_changes[_]
	resource.type == "google_compute_firewall"

	action := resource.change.actions[_]
	action != "delete" # Ignore deleted rules
	action != "no-op" # Ignore no-op rules

	resource.change.after.direction == "INGRESS"

	rule_action := common.rule_action(resource.change.after.allow)
	rule_action == "ALLOW"
	common.is_trusted_source(resource.change.after)
	not common.is_any_tcp_or_udp(resource.change.after)
	not common.is_denied_ports(resource.change.after)

	result := common.template_result(
		"LOW",
		resource,
		sprintf("Firewall rule '%s' allows traffic from one or more trusted sources to an allowed set of ports or port ranges", [resource.change.after.name]),
	)
}

# # Checks if a given CIDR is contained within any of the RFC 1918 ranges
# cidr["is_contained"](source_ranges, trusted_cidrs) {
# 	some i
# 	trusted_cidr := trusted_cidrs[i]

# 	net.cidr_contains(trusted_cidr, source_ranges)
# }

convert_cidr_list_to_string(cidr_list) = result {
	result := concat(", ", [sr | sr := cidr_list[_]])
}
