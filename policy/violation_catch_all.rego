package catch_all

import data.common
# import future.keywords.in

# Used to track if a firewall rule is being deleted
deny_alpha[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action != "delete"  # Only capture deleted rules
    action != "no-op"
    source_ranges := resource.change.after.source_ranges
    count(source_ranges) == 0

    result := {
        "msg": sprintf("Firewall rule '%s' allows traffic from a trusted CIDR Range (%s)", [resource.change.after.name, source_ranges]),
        "action": action,
        "severity": "LOW",
        "ruleID": resource.index,
        "ruleName": resource.change.after.name,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}

deny_catch_all[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    
    action := resource.change.actions[_]
    action != "delete"  # Only capture deleted rules
    action != "no-op"


    result := {
        "msg": sprintf("Firewall rule '%s' allows traffic from a trusted CIDR Range (%s)", [resource.change.after.name, "CATCH_ALL"]),
        "action": action,
        "severity": "CATCH_ALL",
        "ruleID": resource.index,
        "ruleName": resource.change.after.name,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
    }
}

# List top-level keys in the data document, excluding dynamic rules
# list_rules[result] {
#     some path
#     node := data[path]
#     walk(node, [p, v])
#     is_rule(v)
#     not is_self(concat("/", p))  # Use the full path as a string to exclude this rule

#     result := concat("/", p)
# }

# is_rule(v) {
#     v = {"rules": _}
# }

# is_self(p) {
#     p == "data/catch_all/list_rules"
# }

# # Catch-all policy
# violation_catch_all[result] {
#     resource := input.resource_changes[_]

#     resource.type == "google_compute_firewall"
    
#     action := resource.change.actions[_]
#     action != "delete"  # Ignore deleted rules
#     action != "no-op"  # Ignore no-op rules

#     not any_specific_policy_triggered
#     # result := "No specific policy matched"

#     result := common.template_result(
#         "ERROR",
#         resource,
#         sprintf("Firewall rule '%s' does not match any existing policy", [resource.change.after.name]),
#     )
# }

# # Dynamically check if any specific policy has been triggered
# any_specific_policy_triggered {
#     some rule_name
#     rule := data.mypolicy[rule_name]
#     startswith(rule_name, "specific_policy_")  # Assuming specific policies start with 'specific_policy_'
#     _ := rule[_]  # Attempt to evaluate the rule
# }