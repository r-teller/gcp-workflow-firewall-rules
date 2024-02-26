# Define package name
package common



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
