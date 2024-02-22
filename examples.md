```shell
### List all severities associated to a rule
jq 'reduce .[]?.failures[]? as $failure (
    {}; 
    .[$failure.metadata.ruleID] += [$failure.metadata.severity] | map_values(unique) | map_values(sort)
)' .staging.result.json
```

```shell
### List all rules that do not match anything 
jq 'reduce .[]?.failures[]? as $failure (
    {}; 
    .[$failure.metadata.ruleID] += [$failure.metadata.severity] | map_values(unique) | map_values(sort)
) | with_entries(select(.value | length == 1))' .staging.result.json

```