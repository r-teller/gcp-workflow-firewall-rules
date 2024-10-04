# Define package name
package common

# List of trusted ports with associated protocols
# This list defines the ports that are considered trusted for specific protocols.
trusted_ports := [
	{"protocol": "udp", "ports": ["53","100-200"]},
	{"protocol": "tcp", "ports": ["53","22","8000-9000"]},
	# Allows Firewall rules that allow all ICMP traffic
	{"protocol": "icmp", "ports": []},
	# Allows Firewall rules that allow a range of ICMP traffic
	{"protocol": "icmp", "ports": ["0-10"]}
]

# List of disallowed ports with associated severities
sensitive_ports := [
	# Classises TCP/20-21 or ACTIVE/PASSIVE FTP as a sensitive port
	# Classises TCP/3389 or RDP as a sensitive port
	# Classises TCP/80 or HTTP as a sensitive port	
	# Classises TCP/23 or TELNET as a sensitive port
	{"protocol": "tcp", "ports": ["20-21","200-300","23","80","3389"]}
]

# set_of_ports extracts the set of ports for a given protocol from the incoming configuration.
# It iterates over the incoming configuration to find entries matching the specified protocol
# and collects the ports associated with that protocol.
#
# Parameters:
# - _incoming: A list of configurations, each containing a protocol and associated ports.
# - _protocol: The protocol for which ports are to be extracted.
#
# Returns:
# - Set: A set of ports associated with the specified protocol.
set_of_ports(_incoming,_protocol) := {ports | 
	some i
	_incoming[i].protocol == _protocol
	ports := (protocol_empty(_incoming[i].ports) | protocol_ports(_incoming[i].ports))[_]
}

# protocol_empty checks if the incoming port list is empty
# If empty, it returns a set containing "*" to represent all ports
# Parameters:
# - _incoming: The list of ports to check
# Returns:
# - Set: A set containing "*" if the input is empty, otherwise an empty set
protocol_empty(_incoming) := {ports |
	count(_incoming) == 0
	ports := "*"
}

# protocol_ports processes non-empty port lists
# It returns a set containing each port from the input list
# Parameters:
# - _incoming: The list of ports to process
# Returns:
# - Set: A set containing each port from the input list
protocol_ports(_incoming) := {ports | 
	count(_incoming) > 0 
	ports := _incoming[_]
}

# set_of_trusted_ports identifies trusted ports across multiple protocols
# It combines results from different trusted port checking functions
# Parameters:
# - _targeted_ports: A map of targeted ports for each protocol
# - _configured_ports: A map of configured ports for each protocol
# - _protocols: A list of protocols to check
# Returns:
# - Object: A map where keys are protocols and values are sets of trusted ports
set_of_trusted_ports(_targeted_ports,_configured_ports,_protocols) := {protocol:ports |
	protocol := _protocols[_];
	ports := (         
		set_of_trusted_ports_in_list(
			_targeted_ports[protocol],
			_configured_ports[protocol]
		)
		|set_of_trusted_ports_in_ranges(
			_targeted_ports[protocol],
			_configured_ports[protocol]
		)
		| set_of_trusted_port_ranges_in_ranges(
			_targeted_ports[protocol],
			_configured_ports[protocol]
		)
	)
	count(ports) > 0
}

# set_of_trusted_ports_in_list identifies ports that are directly trusted.
# It checks if the configured ports are directly listed in the trusted ports without being part of a range.
#
# Parameters:
# - _trusted_ports: A list of trusted ports.
# - _configured_ports: A list of configured ports to be checked.
#
# Returns:
# - Set: A set of ports that are directly trusted.
set_of_trusted_ports_in_list(_trusted_ports,_configured_ports) := {trusted_ports | 
	some i
	configured_ports := _configured_ports[i]
	not contains(configured_ports,"-")
	trusted_ports := configured_ports
	list_contains( _trusted_ports,configured_ports)
}

# set_of_trusted_ports_in_ranges identifies ports that fall within trusted port ranges.
# It checks if each configured port is within any of the trusted port ranges.
#
# Parameters:
# - _trusted_ports: A list of trusted port ranges.
# - _configured_ports: A list of configured ports to be checked.
#
# Returns:
# - Set: A set of ports that fall within trusted port ranges.
set_of_trusted_ports_in_ranges(_trusted_ports,_configured_ports) := {trusted_ports|
	some i,j
	configured_port := _configured_ports[i]

	trusted_port_range := _trusted_ports[j]
	contains(trusted_port_range, "-")
	trusted_port_range_split := split(trusted_port_range, "-")
	trusted_port_start := to_number(trusted_port_range_split[0])
	trusted_port_end := to_number(trusted_port_range_split[1])
	trusted_ports := configured_port
	to_number(trusted_ports) >= trusted_port_start
	to_number(trusted_ports) <= trusted_port_end
}

# set_of_trusted_port_ranges_in_ranges identifies configured port ranges that are fully contained within trusted port ranges.
# It checks if each configured port range is entirely within any of the trusted port ranges.
#
# Parameters:
# - _trusted_ports: A list of trusted port ranges.
# - _configured_ports: A list of configured port ranges to be checked.
#
# Returns:
# - Set: A set of configured port ranges that are fully contained within trusted port ranges.
set_of_trusted_port_ranges_in_ranges(_trusted_ports,_configured_ports) := {trusted_port_ranges |
	some i,j
	configured_port_range := _configured_ports[i]
	contains(configured_port_range, "-")

	configured_port_range_split := split(configured_port_range, "-")
	configured_port_range_start := to_number(configured_port_range_split[0])
	configured_port_range_end := to_number(configured_port_range_split[1])

	trusted_port_range := _trusted_ports[j]
	contains(trusted_port_range, "-")

	trusted_port_range_split := split(trusted_port_range, "-")
	trusted_port_range_start := to_number(trusted_port_range_split[0])
	trusted_port_range_end := to_number(trusted_port_range_split[1])

	trusted_port_ranges = configured_port_range
	configured_port_range_start >= trusted_port_range_start
	configured_port_range_end <= trusted_port_range_end
}

# set_of_sensitive_ports identifies sensitive ports across multiple protocols
# It combines results from different sensitive port checking functions
#
# Parameters:
# - _targeted_ports: A map of targeted ports for each protocol
# - _configured_ports: A map of configured ports for each protocol
# - _protocols: A list of protocols to check
#
set_of_sensitive_ports(_targeted_ports,_configured_ports,_protocols) := {protocol:ports |
	protocol := _protocols[_];
	ports := (    
		set_of_sensitive_ports_in_list(
			_targeted_ports[protocol],
			_configured_ports[protocol]
		)
		| set_of_configured_port_ranges_containing_sensitive_ranges(
			_targeted_ports[protocol],
			_configured_ports[protocol],
		)
		| set_of_configured_ports_in_sensitive_ranges(
			_targeted_ports[protocol],
			_configured_ports[protocol]
		)
		| set_of_configured_port_ranges_overlapping_sensitive_ports(
			_targeted_ports[protocol],
			_configured_ports[protocol]
		)
	)
	count(ports) > 0
}

# set_of_sensitive_ports_in_list identifies sensitive ports that are directly listed in the sensitive ports list without being part of a range.
# It checks if each configured port is directly listed in the sensitive ports list.
#
# Parameters:
# - _sensitive_ports: A list of sensitive ports.
# - _configured_ports: A list of configured ports to be checked.
#
# Returns:
# - Set: A set of ports that are directly listed in the sensitive ports list.
set_of_sensitive_ports_in_list(_sensitive_ports,_configured_ports) := {sensitive_ports | 
	some i
	configured_ports := _configured_ports[i]
	not contains(configured_ports,"-")
	sensitive_ports := configured_ports
	list_contains( _sensitive_ports,configured_ports)
}

# set_of_configured_port_ranges_containing_sensitive_ranges identifies sensitive port ranges that are fully contained within configured port ranges.
# It checks if each sensitive port range is entirely within any of the configured port ranges.
#
# Parameters:
# - _sensitive_ports: A list of sensitive port ranges.
# - _configured_ports: A list of configured port ranges to be checked.
#
# Returns:
# - Set: A set of sensitive port ranges that are fully contained within configured port ranges.
set_of_configured_port_ranges_containing_sensitive_ranges(_sensitive_ports,_configured_ports) := {sensitive_port_ranges |
	some i,j
	configured_port_range := _configured_ports[i]
	contains(configured_port_range, "-")

	configured_port_range_split := split(configured_port_range, "-")
	configured_port_range_start := to_number(configured_port_range_split[0])
	configured_port_range_end := to_number(configured_port_range_split[1])

	sensitive_port_range := _sensitive_ports[j]
	contains(sensitive_port_range, "-")

	sensitive_port_range_split := split(sensitive_port_range, "-")
	sensitive_port_range_start := to_number(sensitive_port_range_split[0])
	sensitive_port_range_end := to_number(sensitive_port_range_split[1])

	sensitive_port_ranges = configured_port_range
	sensitive_port_range_start >= configured_port_range_start
	sensitive_port_range_end <= configured_port_range_end	
}

# set_of_configured_ports_in_sensitive_ranges identifies configured ports that fall within sensitive port ranges.
# It checks if each configured port is within any of the sensitive port ranges.
#
# Parameters:
# - _sensitive_ports: A list of sensitive port ranges.
# - _configured_ports: A list of configured ports to be checked.
#
# Returns:
# - Set: A set of configured ports that fall within sensitive port ranges.
set_of_configured_ports_in_sensitive_ranges(_sensitive_ports,_configured_ports) := {sensitive_ports |
	some i,j
	configured_ports := _configured_ports[i]

	sensitive_port_ranges := _sensitive_ports[j]
	contains(sensitive_port_ranges, "-")
	
	# Split the sensitive port range into start and end values
	sensitive_port_ranges_split := split(sensitive_port_ranges, "-")
	sensitive_port_range_start := to_number(sensitive_port_ranges_split[0])
	sensitive_port_range_end := to_number(sensitive_port_ranges_split[1])

	# Check if the configured port falls within the sensitive port range
	sensitive_ports := configured_ports
	sensitive_port_range_start <= to_number(sensitive_ports)
	sensitive_port_range_end >= to_number(sensitive_ports)
}

# set_of_configured_port_ranges_overlapping_sensitive_ports identifies configured port ranges that overlap with sensitive ports.
# It checks if any configured port range contains a sensitive port.
#
# Parameters:
# - _sensitive_ports: A list of sensitive ports.
# - _configured_ports: A list of configured port ranges to be checked.
#
# Returns:
# - Set: A set of configured port ranges that overlap with sensitive ports.
set_of_configured_port_ranges_overlapping_sensitive_ports(_sensitive_ports,_configured_ports) := {sensitive_port_ranges|
	some i,j
	configured_port_range := _configured_ports[i]
	contains(configured_port_range, "-")
	
	# Split the configured port range into start and end values
	configured_port_range_split := split(configured_port_range, "-")
	configured_port_range_start := to_number(configured_port_range_split[0])
	configured_port_range_end := to_number(configured_port_range_split[1])

	sensitive_ports := _sensitive_ports[j]

	# Check if the sensitive port is within the configured port range
	sensitive_port_ranges := configured_port_range
	configured_port_range_start <= to_number(sensitive_ports)
	configured_port_range_end >= to_number(sensitive_ports)
}

# is_configured_port_range_overlapping_sensitive_ranges checks if a configured port range overlaps with sensitive port ranges.
# It compares the start and end of the configured range with the start and end of sensitive ranges.
#
# Parameters:
# - _sensitive_port_ranges: A string representing a sensitive port range (e.g., "80-100").
# - _configured_port_ranges: A string representing a configured port range to be checked.
#
# Returns:
# - Boolean: True if there's an overlap, false otherwise.
is_configured_port_range_overlapping_sensitive_ranges(_sensitive_port_ranges,_configured_port_ranges) {	
	# Split and convert the configured port range
	configured_port_range_split := split(_configured_port_ranges, "-")
	configured_port_range_start := to_number(configured_port_range_split[0])
	configured_port_range_end := to_number(configured_port_range_split[1])

	# Split and convert the sensitive port range
	sensitive_port_ranges := split(_sensitive_port_ranges, "-")
	sensitive_port_range_start := to_number(sensitive_port_ranges[0])

	# Check if the configured range overlaps with the start of the sensitive range
	configured_port_range_start <= sensitive_port_range_start
	configured_port_range_end >= sensitive_port_range_start
} else {
	# Split and convert the configured port range
	configured_port_range_split := split(_configured_port_ranges, "-")
	configured_port_range_start := to_number(configured_port_range_split[0])
	configured_port_range_end := to_number(configured_port_range_split[1])

	# Split and convert the sensitive port range
	sensitive_port_ranges := split(_sensitive_port_ranges, "-")
	sensitive_port_range_end := to_number(sensitive_port_ranges[1])

	# Check if the configured range overlaps with the end of the sensitive range
	configured_port_range_start <= sensitive_port_range_end
	configured_port_range_end >= sensitive_port_range_end
}