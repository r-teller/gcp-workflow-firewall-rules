# Define package name
package common

# rule_action determines the action to be taken based on the presence or absence of specific rule actions
# within a given input. This function plays a critical role in policy enforcement by dynamically setting
# the action (ALLOW or DENY) based on the evaluation of rule actions associated with a resource or request.
#
# The decision logic is straightforward:
# - If there is at least one rule action present (implying that some conditions for allowing are met),
#   the function returns "ALLOW".
# - If no rule actions are present (implying that no conditions for allowing are met or that conditions
#   for denial are met), the function returns "DENY".
#
# Parameters:
# - ruleAction: An array or set of rule actions associated with the evaluation of a policy rule.
#               This parameter is expected to reflect the presence of conditions that would trigger
#               an "ALLOW" action when met.
#
# Returns:
# - action: A string that is either "ALLOW" if rule actions are present, or "DENY" if no rule actions
#           are present. This outcome directly influences the enforcement decision for the policy rule.
rule_action(ruleAction) = action {
	count(ruleAction) > 0
	action = "ALLOW"
} else = action {
	count(ruleAction) == 0
	action = "DENY"
}

# List of INTERNAL RFC CIDR ranges
rfc1918_cidrs := {
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

# List of Carrier-grade NAT CIDR ranges
rfc6598_cidrs := {"100.64.0.0/10"}

# List of Google Cloud IAP (Identity-Aware Proxy) CIDR ranges
google_iap_cidrs := {"35.235.240.0/20"}

# List of Google Global Front End (GFE) CIDR ranges
google_gfe_cidrs := {
	"130.211.0.0/22",
	"35.191.0.0/16",
}

# Combine all trusted CIDR ranges into a single set
trusted_cidrs := ((rfc1918_cidrs | rfc6598_cidrs) | google_iap_cidrs) | google_gfe_cidrs

# List of disallowed ports with associated severities
disallowed_ports := [{"protocol": "tcp", "port": "80"}]

# is_trusted_source evaluates whether the given input_value represents a trusted source.
# It considers a source trusted based on one of the following criteria:
# 1. The presence of source IP ranges (source_ranges) that are all contained within the trusted CIDRs.
# 2. The presence of source tags (source_tags) when no source_ranges are specified.
# 3. The presence of source service accounts (source_service_accounts) when no source_ranges are specified.
#
# The function first checks if source_ranges are provided and verifies each CIDR against the trusted CIDRs.
# If no source_ranges are provided, it then checks for the presence of either source_tags or source_service_accounts
# as alternative indicators of a trusted source. The source is considered trusted if it meets any of the above criteria.
#
# Parameters:
# - input_value: An object that may contain fields named source_ranges, source_tags, and source_service_accounts.
#
# Returns:
# - Boolean: True if the source is considered trusted based on the provided criteria, otherwise false.
is_trusted_source(input_value) {
	# If source_ranges are specified, check them against trusted CIDRs and verify that the list is not empty
	count(input_value.source_ranges) > 0
	not not_trusted_cidr(input_value)
} else {
	# If no source_ranges are provided but source_tags are provided
	count(input_value.source_tags) > 0
	input_value.source_ranges == null
} else {
	# If no source_ranges are provided but source_service_accounts are provided
	count(input_value.source_service_accounts) > 0
	input_value.source_ranges == null
}

# not_trusted_cidr checks if any CIDR in the provided input_value's source_ranges
# is not contained within the set of trusted CIDRs. It iterates over each CIDR in
# input_value.source_ranges and applies a negation to the result of any_trusted_cidr_contains.
#
# The function returns true if at least one CIDR from input_value.source_ranges is not
# found within any of the trusted_cidrs, indicating the presence of an untrusted CIDR.
# This is used to flag input values that should not be trusted, potentially preventing
# actions or events for those inputs considered not safe based on their CIDR.
#
# Parameters:
# - input_value: An object that contains a field named source_ranges, which is a list of CIDR strings.
#
# Returns:
# - Boolean: True if any CIDR in input_value.source_ranges is not contained within the trusted CIDRs,
#   otherwise false.
not_trusted_cidr(input_value) {
	cidr := input_value.source_ranges[_]
	not any_trusted_cidr_contains(cidr)
}

# any_trusted_cidr_contains checks if a given CIDR is contained within any of the trusted CIDRs.
# This function iterates over the set of trusted CIDRs and uses the net.cidr_contains built-in
# function to determine if the given CIDR is a subset of or equal to any trusted CIDR in the set.
#
# This check is crucial for identifying whether a specific CIDR from an input source (e.g., a request's
# source IP range) is considered trusted based on the predefined list of trusted CIDRs. It supports
# the security policy by allowing further actions to be conditioned on the trustworthiness of the source CIDR.
#
# Parameters:
# - cidr: A string representing a CIDR that will be checked against the set of trusted CIDRs.
#
# Returns:
# - Boolean: True if the given CIDR is contained within any of the trusted CIDRs, otherwise false.
any_trusted_cidr_contains(cidr) {
	some i
	trusted_cidr := trusted_cidrs[i]
	net.cidr_contains(trusted_cidr, cidr)
}

is_denied_ports(input_value) {
	is_in_specified_ports(input_value.allow[_].ports, disallowed_ports[_].port)
} else {
	is_in_port_range(input_value.allow[_].ports, disallowed_ports[_].port)
}

# Checks if the port is specified directly
is_in_specified_ports(ports, target_port) {
	ports[_] == target_port
}

# Checks if the port is specified within a range
is_in_port_range(ports, target_port) {
	port_range := split(ports[_], "-")
	start := to_number(port_range[0])
	end := to_number(port_range[1])
	target := to_number(target_port)
	target >= start
	target <= end
}

# combine_sources combines all source_ranges, source_service_accounts, and source_tags
# from a given resource into a single string. Each source type is concatenated with a comma,
# and the different source types are separated by semicolons.
combine_sources(input_value) = result {
	source_ranges := prefix_items("CIDR", input_value.source_ranges)
	source_service_accounts := prefix_items("SERVICE_ACCOUNT", input_value.source_service_accounts)
	source_tags := prefix_items("TAG", input_value.source_tags)

	# Filter out empty strings before joining
	non_empty_sources := ({x | x := source_ranges; x != ""} | {x | x := source_service_accounts; x != ""}) | {x | x := source_tags; x != ""}

	result := concat("; ", non_empty_sources)
}

prefix_items(prefix, sources) = result {
	not is_null(sources)
	not count(sources) == 0
	result = sprintf("%s:%s", [prefix, concat(",", sources)])
} else := ""

# is_any_tcp_or_udp checks if there is any allow rule within the input_value that specifies either TCP or UDP protocol
# and has no ports defined (i.e., count of ports is 0). This function is useful for identifying broad network access
# permissions that do not restrict traffic to specific ports, potentially indicating a more permissive security posture
# than intended.
#
# Parameters:
# - input_value: An object that contains an 'allow' field, which is a list of rules. Each rule is expected to have
#   a 'ports' field (list of ports) and a 'protocol' field.
#
# Returns:
# - Boolean: True if there is at least one rule that allows traffic for either TCP or UDP protocol without specifying
#   any ports, otherwise false.
is_any_tcp_or_udp(input_value) {
	allow_rule := input_value.allow[_]
	count(allow_rule.ports) == 0
	allow_rule.protocol == ["udp", "tcp"][_]
}

# # check_allow_ports_protocol checks if the count of allowed ports is 0 and if the allowed protocol is either TCP or UDP.
# # This function returns true if the conditions are met, false otherwise.
# check_allow_ports_protocol(resource) = result {
# 	count(resource.allow) == 0

# 	any_port_count_zero(resource.allow)
# 	result := true
# }

# # check_protocol verifies if the protocol for an allow rule is either TCP or UDP.
# check_protocol(allow_rule) = result {
# 	result := allow_rule.protocol == "TCP" || allow_rule.protocol == "UDP"
# }

# # any_port_count_zero checks if any of the allow rules have a port count of 0.
# any_port_count_zero(allow_rules) = result {
# 	result := any({x | allow_rule := allow_rules[_]; x := count(allow_rule.ports) == 0})
# }

# template_result constructs a result object based on the evaluation of a resource against a policy rule.
# It formats the result with various details including the action taken, severity of the finding,
# rule identification, and additional metadata about the resource being evaluated. This structured
# result is useful for reporting and logging the outcome of policy evaluations.
#
# Parameters:
# - severity: A string indicating the severity level of the result (e.g., CRITICAL, HIGH, MEDIUM, LOW).
# - resource: An object representing the resource being evaluated, containing details about the resource's
#   state before and after the change, the actions taken, and other metadata.
# - message: A string providing a descriptive message or additional information about the evaluation result.
#
# Returns:
# - Object: A structured object containing the following fields:
#   - action: The specific actions taken on the resource as part of the change.
#   - severity: The severity level of the finding.
#   - ruleID: An identifier for the rule that was evaluated.
#   - ruleName: The name of the rule that was evaluated.
#   - ruleAction: The action determined by the rule evaluation (e.g., ALLOW, DENY).
#   - project: The project within which the resource resides.
#   - network: The network associated with the resource.
#   - msg/message: A descriptive message about the evaluation result.
#
# This function is pivotal for generating actionable insights from policy evaluations, allowing
# for clear communication of the outcomes and facilitating decision-making processes based on the results.
template_result(severity, resource, message) := {
	"action": resource.change.actions[_],
	"severity": severity, # CRITICAL | HIGH | MEDIUM | LOW,
	"ruleID": resource.index,
	"ruleName": resource.change.after.name,
	"ruleAction": rule_action(resource.change.after.allow[_]),
	"project": resource.change.after.project,
	"network": resource.change.after.network,
	"msg": message,
	"message": message,
}
