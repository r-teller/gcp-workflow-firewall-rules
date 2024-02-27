# Define package name
package common

# template_result constructs a result object based on the evaluation of a resource against a policy rule.
# It formats the result with various details including the action taken, severity of the finding,
# rule identification, and additional metadata about the resource being evaluated. This structured
# result is useful for reporting and logging the outcome of policy evaluations.
#
# Parameters:
# - severity: A string indicating the severity level of the result (e.g., CRITICAL, HIGH, MEDIUM, LOW).
# - resource: An object representing the resource being evaluated, containing details about the resource's
#   state before and after the change, the actions taken, and other metadata.
# - message: A string providing a descriptive message or additional information about the evaluation result.
#
# Returns:
# - Object: A structured object containing the following fields:
#   - action: The specific actions taken on the resource as part of the change.
#   - severity: The severity level of the finding.
#   - ruleID: An identifier for the rule that was evaluated.
#   - ruleName: The name of the rule that was evaluated.
#   - ruleAction: The action determined by the rule evaluation (e.g., ALLOW, DENY).
#   - project: The project within which the resource resides.
#   - network: The network associated with the resource.
#   - msg/message: A descriptive message about the evaluation result.
#
# This function is pivotal for generating actionable insights from policy evaluations, allowing
# for clear communication of the outcomes and facilitating decision-making processes based on the results.
template_result(severity, resource, message) := {
	"action": resource.change.actions[_],
	"severity": severity, # CRITICAL | HIGH | MEDIUM | LOW,
	"ruleRating": risk_rating(severity),
	"ruleKey": resource.index,
	"ruleName": select_resource_change(resource.change).name,
	"ruleAction": rule_action(select_resource_change(resource.change).allow[_]),
	"ruleDirection": select_resource_change(resource.change).direction,
	"rulePriority": select_resource_change(resource.change).priority,
	"project": select_resource_change(resource.change).project,
	"network": extract_last_path_component(select_resource_change(resource.change).network),
	"msg": message,
	"message": message,
}

# select_resource_change determines the relevant state of a resource based on its change action.
# This function is crucial for policies that need to evaluate the state of a resource before or after a change.
# It helps in identifying what the resource's configuration was (or would be) at the time of policy evaluation.
#
# Parameters:
# - resource_changes: An object that contains details about the changes being made to the resource,
#   including the actions (create, update, delete) and the state of the resource before and after the change.
#
# Returns:
# - result_change: An object representing the state of the resource relevant to the policy evaluation.
#   If the action is "delete", it returns the 'before' state, as the resource is going to be removed.
#   For all other actions, it returns the 'after' state, representing the new or modified state of the resource.
select_resource_change(resource_changes) = result_change {
	resource_changes.actions[_] == "delete"
	result_change = resource_changes.before
} else = result_change {
	result_change = resource_changes.after
}


# extract_last_path_component extracts the last path component from a given string.
# This is useful for parsing URLs or any string that uses '/' to separate components,
# and it's specifically tailored for extracting names from GCP resource URLs.
extract_last_path_component(input_string) = last_component {
    path_components := split(input_string, "/")
    last_index := count(path_components) - 1
    last_component := path_components[last_index]
}

# risk_rating calculates a numerical rating based on the severity level of a finding.
# This function maps textual severity levels to numerical ratings to facilitate
# easier comparison and handling of severity levels in policies. The function
# supports four severity levels: LOW, MEDIUM, HIGH, and CRITICAL, which are
# mapped to numerical ratings from 1 to 4, respectively. If the severity level
# does not match any of the known levels, a default rating of 999 is returned,
# indicating an undefined or unknown severity level.
#
# Parameters:
# - severity: A string representing the severity level of a finding. Expected
#   values are "LOW", "MEDIUM", "HIGH", or "CRITICAL".
#
# Returns:
# - rating: An integer representing the numerical rating of the severity level.
#   The ratings are as follows: LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4.
#   If the severity level is unknown, the function returns 999.
risk_rating(severity) = rating {
    severity == "LOW"
    rating = 1
} else = rating {
    severity == "MEDIUM"
    rating = 2
} else = rating {
    severity == "HIGH"
    rating = 3
} else = rating {
    severity == "CRITICAL"
    rating = 4
} else = 999

# action_description translates an action keyword into a past-tense description.
#
# This function takes an action keyword as input and returns a string
# describing the action in past tense. It is designed to convert the action
# keywords "create", "update", and "delete" into "created", "updated", and "deleted",
# respectively. This can be useful for generating human-readable messages or logs.
#
# Parameters:
# - action: A string representing the action to be described. Expected values are
#           "create", "update", or "delete".
#
# Returns:
# - result: A string containing the past-tense description of the action.
action_description(action) = result {
	action == "create"
	result = "created"
} else = result {
	action == "update"
	result = "updated"
} else = result {
	action == "delete"
	result = "deleted"
}

# rule_action determines the action to be taken based on the presence or absence of specific rule actions
# within a given input. This function plays a critical role in policy enforcement by dynamically setting
# the action (ALLOW or DENY) based on the evaluation of rule actions associated with a resource or request.
#
# The decision logic is straightforward:
# - If there is at least one rule action present (implying that some conditions for allowing are met),
#   the function returns "ALLOW".
# - If no rule actions are present (implying that no conditions for allowing are met or that conditions
#   for denial are met), the function returns "DENY".
#
# Parameters:
# - ruleAction: An array or set of rule actions associated with the evaluation of a policy rule.
#               This parameter is expected to reflect the presence of conditions that would trigger
#               an "ALLOW" action when met.
#
# Returns:
# - action: A string that is either "ALLOW" if rule actions are present, or "DENY" if no rule actions
#           are present. This outcome directly influences the enforcement decision for the policy rule.
rule_action(rule_action) = action {
	count(rule_action) > 0
	action = "ALLOW"
} else = action {
	count(rule_action) == 0
	action = "DENY"
}