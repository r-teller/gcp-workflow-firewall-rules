package critical_allowed_ports

# List of disallowed ports with associated severities
disallowed_ports := [
    { "protocol": "tcp", "port": "80", "severity": "CRITICAL"},
    # Add other disallowed ports as needed
]

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

    port_directly_allowed(allow_rule.ports, port_info.port)

    result := {
        "msg": sprintf("Firewall rule '%s' directly allows a disallowed %s port (%s), which is not allowed. %s", [resource.change.after.name, port_info.protocol, port_info.port, "cidr_range"]),
        "action": action,
        "severity": port_info.severity,
        "ruleID": resource.index,
        "ruleName": resource.change.after.name,
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
    action != "no-op"  # Ignore no-op rules

    port_info  := disallowed_ports[_]
    allow_rule := resource.change.after.allow[_]    
    allow_rule.protocol == port_info.protocol
    resource.change.after.direction == "INGRESS"
    port_in_range_allowed(allow_rule.ports, port_info.port)
    
    result := {
        "msg": sprintf("Firewall rule '%s' allows a disallowed %s port (%s) within a range, which is not allowed.", [resource.change.after.name, port_info.protocol, port_info.port]),
        "severity": port_info.severity,
        "ruleID": resource.index,
        "ruleName": resource.change.after.name,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}

# Deny if a firewall rule allows all UDP or TCP ports
deny[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action != "delete"  # Ignore deleted rules
    action != "no-op"  # Ignore no-op rules

    port_info  := disallowed_ports[_]
    allow_rule := resource.change.after.allow[_]    
    allow_rule.protocol == ["udp","tcp"][_]
    resource.change.after.direction == "INGRESS"
    count(allow_rule.ports) == 0
    
    result := {
        "msg": sprintf("Firewall rule '%s' allows all ports for protocol %s, which is not allowed.", [resource.change.after.name, allow_rule.protocol]),
        "severity": port_info.severity,
        "ruleID": resource.index,
        "ruleName": resource.change.after.name,
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