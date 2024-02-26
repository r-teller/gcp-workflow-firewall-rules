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
	"ruleRating": riskRating(severity),
	"ruleKey": resource.index,
	"ruleName": resource.change.after.name,
	"ruleAction": rule_action(resource.change.after.allow[_]),
	"ruleDirection": resource.change.after.direction,
	"rulePriority": resource.change.after.priority,
	"project": resource.change.after.project,
	"network": resource.change.after.network,
	"msg": message,
	"message": message,
}

riskRating(severity) = rating {
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
rule_action(ruleAction) = action {
	count(ruleAction) > 0
	action = "ALLOW"
} else = action {
	count(ruleAction) == 0
	action = "DENY"
}