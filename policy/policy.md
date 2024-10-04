# OPA Validation Rules Summary

This document provides a brief overview of each OPA validation rule within the policy directory, designed to enforce security and compliance standards for firewall configurations in Google Cloud Platform (GCP) environments.

## Low Risk Rules

### [low_warn_cud_catch_all.rego](./example_policies/1_low/low_warn_cud_catch_all.rego)
- **Rule**: `warn_catch_all`
- **Description**: Flags low-risk modifications, creations, and deletions of Google Compute Firewall rules, excluding no-ops.

## Medium Risk Rules

### [medium_warn_cu_rules.rego](./example_policies/2_medium/medium_warn_cu_rules.rego)
- **Rules**:
  - `warn_not_trusted_port_rule`
    - **Description**: Identifies changes allowing ingress traffic on untrusted protocols and ports, generating warnings for medium-risk configurations.
  - `warn_not_trusted_source_rule`
    - **Description**: Flags ingress traffic from untrusted source CIDR ranges, providing warnings for medium-risk changes.

### [medium_warn_cu_allow_ingress.rego](./example_policies/2_medium/medium_warn_cu_allow_ingress.rego)
- **Rule**: `warn_non_trusted_sources`
- **Description**: Warns about firewall rules that permit ingress from non-trusted source ranges.

## High Risk Rules

### [high_warn_cu_allow_ingress.rego](./example_policies/3_high/high_warn_cu_allow_ingress.rego)
- **Rule**: `warn_all_tcp_or_udp_ports`
- **Description**: Identifies rules allowing all TCP/UDP ports, marking them as high risk.

## Critical Risk Rules

### [critical_warn_cu_allow_ingress.rego](./example_policies/4_critical/critical_warn_cu_allow_ingress.rego)
- **Rule**: `warn_contains_sensitive_ports`
- **Description**: Flags rules allowing traffic on sensitive TCP/UDP ports as critical risks.

## Blocking Rules

### [blocking_deny_cu_catch_all.rego](./example_policies/5_blocking/blocking_deny_cu_catch_all.rego)
- **Rules**:
  - `deny_incorrect_logging`
    - Blocks rules with unsupported logging configurations.
  - `deny_allow_all_to_all`
    - Prevents rules that allow ingress from any source to any destination.
  - `deny_allow_priority_le_1000`
    - Disallows rules with a priority of 1000 or lower to prevent overriding more specific rules.

## Additional Information

The policies utilize common functions from [`template_result.rego`](./0_common/template_result.rego) for structured result objects and action descriptions, ensuring consistency across validations.

This summary aims to provide quick insights into the purpose and risk level of each validation rule, facilitating easier navigation and understanding of the policy framework.