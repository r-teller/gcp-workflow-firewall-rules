# Define package name
package common

# List of disallowed ports with associated severities
sensitive_ports := [{"protocol": "tcp", "port": "80"}, {"protocol": "tcp", "port": "8080"}]

contains_sensitive_ports(input_value) {
	is_in_sensitive_ports(input_value.allow[_].ports, sensitive_ports[_].port)
} else {
	is_in_sensitive_port_range(input_value.allow[_].ports, sensitive_ports[_].port)
}

# Checks if the port is specified directly
is_in_sensitive_ports(input_value, sensitive_ports) {
	input_value[_] == sensitive_ports
}

# Checks if the port is specified within a range
is_in_sensitive_port_range(input_value, sensitive_ports) {
	port_range := split(input_value[_], "-")
	start := to_number(port_range[0])
	end := to_number(port_range[1])
	target := to_number(sensitive_ports)
	target >= start
	target <= end
}
