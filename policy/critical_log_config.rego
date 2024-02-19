package critical_log_config

# Deny rule to check log_config for metadata settings
deny[result] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"  # Adjust type as necessary
    log_config := resource.change.after.log_config
    not log_config_correctly_set(log_config)

    result := {
        "severity": "CRITICAL",
        "ruleID": resource.index,
        "project":resource.change.after.project,
        "network":resource.change.after.network,
        "msg": sprintf("Resource '%s' does not have log_config set to INCLUDE_ALL_METADATA or EXCLUDE_ALL_METADATA.", [resource.change.after.name])
    }
}

# Helper function to validate log_config
log_config_correctly_set(log_config) {
    # Check if log_config is not empty
    count(log_config) > 0
    # Extract metadata values from log_config entries
    metadata_values := [metadata | 
                        config := log_config[_]; 
                        metadata := config.metadata]
    # Check if any metadata value is one of the allowed values
    allowed_metadata(metadata_values)
}

# Helper function to check if any metadata value is allowed
allowed_metadata(metadata_values) {
    # Allowed values for metadata
    allowed := {"INCLUDE_ALL_METADATA", "EXCLUDE_ALL_METADATA"}
    # Succeed if any metadata value is in the allowed set
    some i
    metadata_values[i] == allowed[_]
}