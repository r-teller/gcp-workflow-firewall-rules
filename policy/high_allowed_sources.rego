package high_allowed_sources

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

    allow_rule := resource.change.after.allow[_]    
    count(allow_rule) > 0
    resource.change.after.direction == "INGRESS"

    source_range := resource.change.after.source_ranges[_]
    not cidr.is_contained(source_range,  trusted_cidrs) 

    result := {
        "msg": sprintf("Firewall rule '%s' allows traffic from a non-trusted CIDR Range (%s)", [resource.change.after.name, source_range]),
        "severity": "HIGH",
        "ruleID": resource.index,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}


# Deny if a firewall rule allows disallowed TCP ports directly
deny[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    action := resource.change.actions[_]
    action != "delete"  # Ignore deleted rules

    allow_rule := resource.change.after.allow[_]    
    count(allow_rule) > 0
    resource.change.after.direction == "INGRESS"

    resource.change.after.source_ranges == null
    resource.change.after.source_tags == null
    resource.change.after.source_service_accounts == null

    result := {
        "msg": sprintf("Firewall rule '%s' allows traffic from all sources", [resource.change.after.name]),
        "severity": "HIGH",
        "ruleID": resource.index,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}

# Checks if a given CIDR is contained within any of the RFC 1918 ranges
cidr.is_contained(source_range, trusted_cidrs) {
    some i
    cidr_range := trusted_cidrs[i]
    
    net.cidr_contains(cidr_range,source_range)
}