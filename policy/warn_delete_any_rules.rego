package deleted_rules

import data.common

# Used to track if a firewall rule is being deleted
warn_deleted_rules[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action == "delete"  # Only capture deleted rules

    result := common.template_result(
        "N/A",
        resource,
        sprintf("Firewall rule '%s' is being deleted", [resource.change.after.name]),
    )
}