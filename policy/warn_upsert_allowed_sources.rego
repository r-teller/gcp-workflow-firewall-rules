package upsert_allowed_sources

import data.common

# WARN if a firewall rule allows traffic from trusted source ranges
warn[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action != "delete"  # Ignore deleted rules
    action != "no-op"  # Ignore no-op rules

    allow_rule := resource.change.after.allow[_]
    count(allow_rule) > 0
    
    resource.change.after.direction == "INGRESS"

    source_ranges := resource.change.after.source_ranges[_]
    # cidr.is_contained(source_range,  common.trusted_cidrs)
    # all([ |cidr.is_contained(resource.change.after.source_ranges[_],  common.trusted_cidrs) ])
    # Severity == CRITICAL | HIGH | MEDIUM | LOW
    # Resouce == Attributes of resource Changes
    # MSG == Message to be displayed when this event is triggered
    source_ranges_list := concat(", ",[sr | sr := resource.change.after.source_ranges[_]])
    # source_ranges_list := concat(",", resource.change.after.source_ranges[_])
    result := common.template_result(        
        "LOW",
        resource,
        sprintf("Firewall rule '%s' allows traffic from a trusted CIDR Range (%s)", [resource.change.after.name, source_ranges_list ]),
    )
}

# Checks if a given CIDR is contained within any of the RFC 1918 ranges
cidr.is_contained(source_ranges, trusted_cidrs) {
    some i
    trusted_cidr := trusted_cidrs[i]
    
    net.cidr_contains(trusted_cidr,source_ranges)
}