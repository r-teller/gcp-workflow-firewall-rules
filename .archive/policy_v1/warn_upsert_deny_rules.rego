package upsert_deny_rules

import data.common

# Used to track if a firewall rule is being deleted
warn_deny_rules[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action != "delete"  # Ignore deleted rules
    action != "no-op"  # Ignore no-op rules

    deny_rule := resource.change.after.deny[_]    
    count(deny_rule) > 0

    result := common.template_result(
        "N/A",
        resource,
        sprintf("Firewall rule '%s' is being deleted", [resource.change.after.name]),
    )
}