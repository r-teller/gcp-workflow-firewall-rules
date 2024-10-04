# Define package name
package common

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
is_trusted_cidrs_source(input_value) {
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

set_of_not_trusted_cidrs(input_value) := {cidr |
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
