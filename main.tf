locals {
  firewall_rule_path = "./rules"
  firewall_rule_sets = fileset(local.firewall_rule_path, "**/*.json")
  firewall_rules = flatten([for rules_file in local.firewall_rule_sets : [
    for k1, v1 in jsondecode(file("${local.firewall_rule_path}/${rules_file}")) : merge(
      v1,
      regex("(?P<project_id>[^/]*)/(?P<network>[^/]*)/(?P<file_name>.*$)", rules_file),
      { rule_index = k1 },
    ) if length(v1) > 0
    ]
  ])
}

variable "generate_firewall_rules_map_json" {
  type    = bool
  default = false
}

module "firewall_rules" {
  # source = "../.."
  source  = "r-teller/firewall-rules/google"
  version = ">=3.0.0"

  ## Optional field and can be explicitly specified here or within the firewall_rule
  #   project_id = var.project_id
  #   network    = var.network

  firewall_rules = local.firewall_rules

  # Optional field used to include implicit sources within Firewall rules
  include_implicit_addresses = false

  ## Optional field for using legacy dynamic naming
  # use_legacy_naming = true

  ## Optional field that can be used to limit attributes used in dynamic naming
  # override_dynamic_naming = {
  #   include_prefix      = true
  #   include_environment = true
  #   include_project_id  = true
  #   include_network     = true
  #   include_name        = true
  #   include_id          = true
  # }
}

### Creates JSON file that contains a list of all configured rules
resource "local_file" "firewall_rules_map" {
  count    = var.generate_firewall_rules_map_json ? 1 : 0
  content  = jsonencode(module.firewall_rules.firewall_rules_map)
  filename = "${path.module}/outputs/managed.json"
}