package common

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

ruleAction(ruleAction) = action {
    count(ruleAction) > 0
    action = "ALLOW"
} else = action {
    count(ruleAction) == 0
    action = "DENY"
}


template_result(severity,resource,message) := {    
    "action"  :  resource.change.actions[_],
    "severity"  :  severity, # CRITICAL | HIGH | MEDIUM | LOW,
    "ruleID"  :  resource.index,
    "ruleName"  :  resource.change.after.name,
    "ruleAction" : ruleAction(resource.change.after.allow[_]),
    "project"  :  resource.change.after.project,
    "network"  :  resource.change.after.network,
    "msg": message,
    "message": message,
    
}