# OPA Validation Rules Summary

This document provides a brief overview of each OPA validation rule within the policy directory, designed to enforce security and compliance standards for firewall configurations in Google Cloud Platform (GCP) environments.

## Low Risk Rules

### [cud_catch_all.rego](./1_low/cud_catch_all.rego)
- **Rule**: `warn_catch_all`
- **Description**: Flags low-risk modifications, creations, and deletions of Google Compute Firewall rules, excluding no-ops.

## Medium Risk Rules

### [upsert_allow_ingress.rego](./2_medium/upsert_allow_ingress.rego)
- **Rule**: `warn_non_trusted_sources`
- **Description**: Warns about firewall rules that permit ingress from non-trusted source ranges.

## High Risk Rules

### [upsert_allow_ingress.rego](./3_high/upsert_allow_ingress.rego)
- **Rule**: `warn_all_tcp_or_udp_ports`
- **Description**: Identifies rules allowing all TCP/UDP ports, marking them as high risk.

## Critical Risk Rules

### [upsert_allow_ingress.rego](./4_critical/upsert_allow_ingress.rego)
- **Rule**: `warn_contains_sensitive_ports`
- **Description**: Flags rules allowing traffic on sensitive TCP/UDP ports as critical risks.

## Blocking Rules

### [upsert_catch_all.rego](./5_blocking/upsert_catch_all.rego)
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