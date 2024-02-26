# Define package name
package common

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
