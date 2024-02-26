package common

is_any_sources(input_value) {
	# If source_ranges are specified, check them against if they include 0.0.0.0/0 rule
	count(input_value.source_ranges) > 0
	not is_null(input_value.source_ranges)
	input_value.source_ranges[_] == "0.0.0.0/0"
} else {
	count(input_value.source_ranges) > 0
	not is_null(input_value.source_ranges)
	net.cidr_merge(input_value.source_ranges) == {"0.0.0.0/0"}
} else {
	is_null(input_value.source_ranges)
	is_null(input_value.source_tags)
	is_null(input_value.source_service_accounts)
} else = false

is_any_targets(input_value) {
	# If target_ranges are specified, check them against if they include 0.0.0.0/0 rule
	count(input_value.destination_ranges) > 0
	not is_null(input_value.destination_ranges)
} else {
	count(input_value.destination_ranges) > 0
	not is_null(input_value.destination_ranges)
	net.cidr_merge(input_value.destination_ranges) == {"0.0.0.0/0"}
} else {
	is_null(input_value.target_tags)
	is_null(input_value.target_service_accounts)
} else = false
