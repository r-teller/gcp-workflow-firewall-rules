package high_allowed_ports

# List of disallowed ports with associated severities
disallowed_ports := [
    { "protocol": "tcp", "port": "3389", "severity": "HIGH"},
    { "protocol": "tcp", "port": "22", "severity": "HIGH"},
    # Add other disallowed ports as needed
]

# List of INTERNAL RFC CIDR ranges
rfc1918_cidrs := {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
}

rfc6598_cidrs := {
    "100.64.0.0/10",
}

# List of Google CIDR ranges
google_iap_cidrs := {
    "35.235.240.0/20",
}

google_gfe_cidrs := {
 "130.211.0.0/22",
 "35.191.0.0/16",
}

trusted_cidrs := rfc1918_cidrs | rfc6598_cidrs | google_iap_cidrs | google_gfe_cidrs

# Deny if a firewall rule allows disallowed TCP ports directly
deny[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action != "delete"  # Ignore deleted rules
    action != "no-op"  # Ignore no-op rules

    port_info  := disallowed_ports[_]
    allow_rule := resource.change.after.allow[_]    
    allow_rule.protocol == port_info.protocol
    resource.change.after.direction == "INGRESS"

    source_range := resource.change.after.source_ranges[_]

    not cidr.is_contained(source_range,  trusted_cidrs) 


    port_directly_allowed(allow_rule.ports, port_info.port)

    result := {
        "msg": sprintf("Firewall rule '%s' directly allows a disallowed %s port (%s), which is not allowed. %s", [resource.change.after.name, port_info.protocol, port_info.port, "cidr_range"]),
        "severity": port_info.severity,
        "ruleID": resource.index,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}

# Deny if a firewall rule allows disallowed TCP ports within a range
deny[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    action := resource.change.actions[_]
    action != "delete"  # Ignore deleted rules

    port_info  := disallowed_ports[_]
    allow_rule := resource.change.after.allow[_]    
    allow_rule.protocol == port_info.protocol
    resource.change.after.direction == "INGRESS"
    port_in_range_allowed(allow_rule.ports, port_info.port)
    
    result := {
        "msg": sprintf("Firewall rule '%s' allows a disallowed %s port (%s) within a range, which is not allowed.", [resource.change.after.name, port_info.protocol, port_info.port]),
        "severity": port_info.severity,
        "ruleID": resource.index,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}

# Checks if the port is allowed directly
port_directly_allowed(ports, target_port) {
    ports[_] == target_port
}

# Checks if the port is allowed within a range
port_in_range_allowed(ports, target_port) {
    port_range := split(ports[_], "-")
    start := to_number(port_range[0])
    end := to_number(port_range[1])
    target := to_number(target_port)
    target >= start
    target <= end
}

# Checks if a given CIDR is contained within any of the RFC 1918 ranges
cidr.is_contained(source_range, trusted_cidrs) {
    some i
    cidr_range := trusted_cidrs[i]
    
    net.cidr_contains(cidr_range,source_range)
}