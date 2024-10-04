# Purpose: Identifies medium-risk changes in Google Compute Firewall rules that involve untrusted protocols, ports, or source CIDR ranges.
# This rule aims to highlight configurations that may introduce potential security risks by allowing traffic through untrusted channels.
#
# Functionality: The file contains two primary rules:
# 1. `warn_not_trusted_port_rule`: This rule iterates over `input.resource_changes`, focusing on "google_compute_firewall" resources.
#    It checks for changes (excluding no-ops and deletions) that allow ingress traffic on untrusted protocols and ports.
#    If such configurations are detected, the rule generates a warning, detailing the untrusted protocols and ports involved.
# 2. `warn_not_trusted_source_rule`: Similar to the first rule, this one checks for ingress traffic from untrusted source CIDR ranges.
#    It flags changes that involve untrusted sources, providing a message that includes the untrusted CIDR ranges.
#
# Context: In cloud infrastructure, maintaining control over firewall configurations is crucial for security. These rules help
# identify medium-risk changes that could potentially expose the environment to threats, allowing for timely review and mitigation.
#
# Note: These medium-risk rules are part of a layered security approach, designed to catch and address potential risks before
# they escalate. They complement other policies that may enforce stricter criteria or provide additional context, ensuring a
# comprehensive security posture.

package medium_warn_cu_rules

import data.common

warn_not_trusted_port_rule[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    action := resource.change.actions[_]
	action != "no-op"
	action != "delete"

    upper(resource.change.after.direction) == "INGRESS"
    upper(common.rule_action(resource.change.after.allow[_])) == "ALLOW"

    trusted_protocols := {protocols | protocols := common.trusted_ports[_].protocol}
    configured_protocols := {protocols | protocols := resource.change.after.allow[_].protocol}
    protocols := trusted_protocols | configured_protocols

    trusted_ports := {protocol:ports| protocol := trusted_protocols[_];  ports := common.set_of_ports(common.trusted_ports,protocol)}
    configured_ports := {protocol:ports| protocol := configured_protocols[_];  ports := common.set_of_ports(resource.change.after.allow,protocol)}
    
    # Create a set of configured and trusted ports
    merged_set_of_configured_and_trusted_ports := common.set_of_trusted_ports(trusted_ports,configured_ports,protocols)

    # Create a set of configured and untrusted ports
    merged_set_of_configured_and_untrusted_ports := {protocol:ports |
        protocol := protocols[_];
        ports := ({port| 
            port := configured_ports[protocol] - merged_set_of_configured_and_trusted_ports[protocol]
            common.list_contains(object.keys(merged_set_of_configured_and_trusted_ports),protocol)
        }|{port|
            port := configured_ports[protocol]
            not common.list_contains(object.keys(merged_set_of_configured_and_trusted_ports),protocol)
        })[_]
        count(ports) > 0
    }

    count(merged_set_of_configured_and_untrusted_ports) > 0

    # Create a message with untrusted ports
    msg_untrusted_ports := concat(", ", [
        sprintf("%s/%s", [protocol, port])
        | protocol := protocols[_]
        ; port := merged_set_of_configured_and_untrusted_ports[protocol][_]
    ])

    # result := {
    #     "msg":msg_untrusted_ports,
    #     "configured_ports":configured_ports,
    #     "merged_set_of_configured_and_trusted_ports":merged_set_of_configured_and_trusted_ports,
    #     "merged_set_of_configured_and_untrusted_ports":merged_set_of_configured_and_untrusted_ports
    # }

	result := common.template_result(
		"MEDIUM",
		resource,
		sprintf("Firewall Rule '%s' will be %s, and this change is considered medium risk because one or more protocols and ports are not trusted [%s].", [
            resource.change.after.name, 
            common.action_description(action), 
            msg_untrusted_ports
            ]
        ),
	)      
}

warn_not_trusted_source_rule[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"

    action := resource.change.actions[_]
    action != "no-op"
    action != "delete"

    upper(resource.change.after.direction) == "INGRESS"
    upper(common.rule_action(resource.change.after.allow[_])) == "ALLOW"

    count(resource.change.after.source_ranges) > 0

    # Check if the source is trusted 
    not common.is_trusted_cidrs_source(resource.change.after)
    
    # Create a set of not trusted sources
    set_of_not_trusted_cidrs := common.set_of_not_trusted_cidrs(resource.change.after)

    result := common.template_result(
    	"MEDIUM",
    	resource,
    	sprintf("Firewall Rule '%s' will be '%s', and this change is considered medium risk because one or more source cidr ranges [%s] not trusted.", [
            resource.change.after.name, 
            common.action_description(action), 
            concat(",",set_of_not_trusted_cidrs)
            ]
        ),
    )  
}