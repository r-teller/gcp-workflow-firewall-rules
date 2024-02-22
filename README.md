
# Self-Service Firewall Management Guide

## Overview
This guide supports application owners in self-managing firewall rules within a Google Cloud Platform (GCP) environment, using GitHub Actions alongside Terraform and Open Policy Agent (OPA) for a secure, compliant, and automated approach to network configuration management.

## Prerequisites
- Access to the GitHub repository with permissions to create branches and pull requests.
- Basic understanding of JSON for defining firewall rules.

## Workflow Overview
1. Define Firewall Rules: Users submit firewall rule changes by adding or modifying JSON files in a specific directory within the GitHub repository.
2. Automated Review Process: Upon pull request creation, GitHub Actions will automatically perform OPA compliance checks and a Terraform plan to preview changes.
3. Approval and Application: Low-risk changes (as determined by OPA policies) are automatically merged and applied. High-risk changes require manual review and approval.

## Defining Firewall Rules
Firewall rules are defined using JSON format in the `./rules` directory. Each JSON file should contain rules that pertain to specific projects or networks within your organization.

### JSON Rule Format
- **Low-Risk Rule Example (auto-approved):**
  ```json
  [
      {
          "id": "allow-tcp-443-ingress-internal-explicit",
          "name": "allow-tcp-443-ingress-internal-explicit",
          "action": "allow",
          "direction": "INGRESS",
          "log_config": "INCLUDE_ALL_METADATA",
          "sources": ["192.168.0.0/16", "10.0.0.0/21"],
          "rules": [{"protocol": "TCP", "ports": ["443"]}]
      }
  ]
  ```
- **High-Risk Rule Example (requires manual review):**
  ```json
  [
      {
          "id": "allow-tcp-443-ingress-external-explicit",
          "name": "allow-tcp-443-ingress-external-explicit",
          "action": "allow",
          "direction": "INGRESS",
          "log_config": "INCLUDE_ALL_METADATA",
          "sources": ["0.0.0.0/0"],
          "rules": [{"protocol": "TCP", "ports": ["443"]}]
      }
  ]
  ```

## Submission Process
1. Create a Branch: For new firewall rules or modifications, create a new branch in the repository.
2. Add or Modify Rules: Place your JSON-formatted rule definitions in the appropriate directory.
3. Create a Pull Request: Submit your changes for review by creating a pull request against the main branch.

## Automated Review and Deployment
GitHub Actions Workflows automatically perform compliance checks and preview changes upon pull request creation:
- **Compliance Checks:** OPA reviews rule changes for compliance.
- **Change Preview:** Terraform `plan` previews proposed changes.

### Approval Process
- **Auto-Approval:** Low-risk changes passing compliance checks are automatically approved and merged.
- **Manual Review:** High-risk changes require manual approval by authorized personnel.

## Folder Hierarchy for Firewall Rules
Organize firewall rule files within the repository based on their corresponding GCP configurations:
```
./rules/
│
├── <project_id>/
│   ├── <network_name>/
│   │   ├── <rule_set_name>.json
│   ...
```
- **Project ID** folders represent GCP projects.
- **Network Name** subfolders represent VPC networks.
- **Rule Set Name** `.json` files contain firewall rule definitions.

### Mapping to GCP
Ensure folder and file names accurately reflect their GCP counterparts for correct rule application.

## Contributions and Support
- **Contributing:** Follow the submission process for your firewall rule changes, ensuring compliance for smooth approval.
- **Support:** For assistance or issues, open an issue in the GitHub repository or contact the infrastructure team.
