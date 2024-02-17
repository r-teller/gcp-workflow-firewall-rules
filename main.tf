# locals {
#   firewall_rule_path = "./rules"
#   firewall_rule_sets = fileset(local.firewall_rule_path, "**/*.json")
#   firewall_rules = flatten([for rules in local.firewall_rule_sets : [
#     for k1, v1 in jsondecode(file("${local.firewall_rule_path}/${rules}")) : {
#       (k1) = [for k2, v2 in v1[*] : merge(v2, regex("(?P<project>[^/]*)/(?P<network>[^/]*)/(?P<fileName>.*$)", rules))]
#     } if length(v1) > 0
#     ]
#   ])
#   keys = distinct(flatten([for x in local.firewall_rules : keys(x)]))

#   firewall_rules_merged = {
#     for key in local.keys : key => merge(flatten(
#       [for x in local.firewall_rules : x[key] if can(x[key])]
#     )...)
#   }
# }


# output "foo" {
#   #   value = [
#   #     for a in fileset(local.firewall_rule_path, "**/*.json") :
#   #     regex("(?P<project>[^/]*)/(?P<network>[^/]*)/(?P<fileName>.*$)", a)
#   #   ]
#   value = local.firewall_rules_merged
# }


# module "firewall_rules" {
#   source       = "terraform-google-modules/network/google//modules/firewall-rules"
#   version      = "9.0.0"

#   project_id   = var.project_id          #<-- Tier one folder
#   network_name = module.vpc.network_name #<-- Tier two folder

#   ingress_rules = [{
#     name                    = "allow-ssh-ingress"
#     description             = null
#     priority                = null
#     destination_ranges      = ["10.0.0.0/8"]
#     source_ranges           = ["0.0.0.0/0"]
#     source_tags             = null
#     source_service_accounts = null
#     target_tags             = null
#     target_service_accounts = null
#     allow = [{
#       protocol = "tcp"
#       ports    = ["22"]
#     }]
#     deny = []
#     log_config = {
#       metadata = "INCLUDE_ALL_METADATA"
#     }
#   }]

#   egress_rules = [

#   ]
# }
