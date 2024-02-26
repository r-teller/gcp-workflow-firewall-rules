# Define package name
package common

# Helper function to validate log_config
is_log_config_set(log_config) {
	# Check if log_config is not empty
	count(log_config) > 0

	# Extract metadata values from log_config entries
	metadata_values := [metadata |
		config := log_config[_]
		metadata := config.metadata
	]

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