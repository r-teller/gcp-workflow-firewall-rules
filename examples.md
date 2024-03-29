```shell
terraform plan -out="./.staging.tfplan"
terraform show -json "./.staging.tfplan" > ./".staging.tfplan.json"
```

```shell
docker run \
    --rm \
    -v "$(pwd)":/project \
    openpolicyagent/conftest \
    test --all-namespaces ./.staging.tfplan.json --output json > ./.staging.result.json
```


```shell
## Detect failures and insert namespace within metadata
jq 'map((.failures[]?.metadata.namespace) = .namespace) | [.[].failures[]?]' ./.staging.result.json

## Detect warnings | failures and insert namespace within metadata
jq 'map((.failures[]?.metadata.namespace) = .namespace | (.warnings[]?.metadata.namespace) = .namespace) | [.[].failures[]?, .[].warnings[]?]' ./.staging.result.json


jq ' [.[].violations[]?  ]'  ./.staging.result.json

## List all failures and warnings
jq ' [.[].failures[]? , .[].warnings[]?  ]'  ./.staging.result.json

### List all severities associated to a rule
jq 'reduce .[]?.failures[]? as $failure (
    {}; 
    .[$failure.metadata.ruleKey] += [$failure.metadata.severity] | map_values(unique) | map_values(sort)
)' ./.staging.result.json

### Create a list of all rules and their severities
jq 'reduce (.[]?.failures[]?, .[]?.warnings[]?) as $item (
    {}; 
    .[$item.metadata.ruleKey] += [$item.metadata.severity] | map_values(unique) | map_values(sort)
)' ./.staging.result.json
```

```shell
### List all rules that do not match anything other than CATCH_ALL
jq 'reduce (.[]?.failures[]?, .[]?.warnings[]?) as $item (
    {}; 
    .[$item.metadata.ruleKey] += [$item.metadata.severity] | map_values(unique) | map_values(sort)
) | with_entries(select(.value | length == 1))' .staging.result.json


jq 'reduce (.[]?.failures[]?, .[]?.warnings[]?) as $item (
    {}; 
    .[$item.metadata.ruleKey] += [$item.metadata.severity] | map_values(unique) | map_values(sort)
) | with_entries(select(.value | length == 1)) | keys[]' .staging.result.json | xargs -I {} jq '.resource_changes[] | select(.index == "{}") | .change.after' .staging.tfplan.json

```

```shell
# Explanation:
# 1. map(.warnings + .failures | select(. != null)[]): This part combines the warnings and failures arrays from each entry (if they exist) into a single array of objects for further processing.
# 2. group_by(.metadata.ruleKey): Groups the resulting objects by their ruleKey found within the metadata object.
# 3. map({ruleKey: .[0].metadata.ruleKey, totalRuleRating: map(.metadata.ruleRating) | add}): For each group, it creates a new object containing the ruleKey and the totalRuleRating, which is the sum of ruleRating values within that group.
# This command assumes that the structure of your JSON data is consistent with the snippets provided earlier and that .staging.result.json is the correct path to your file. Adjust the file path as necessary for your environment.

jq 'map(.warnings + .failures | select(. != null)[]) | group_by(.metadata.ruleKey) | map({ruleKey: .[0].metadata.ruleKey, totalRuleRating: map(.metadata.ruleRating) | add})| sort_by(.totalRuleRating)' .staging.result.json
jq 'map(.warnings + .failures | select(. != null)[]) | group_by(.metadata.ruleKey) | map({ruleKey: .[0].metadata.ruleKey, totalRuleRating: map(.metadata.ruleRating) | add}) | sort_by(.totalRuleRating) | map(select(.totalRuleRating >= 2 and .totalRuleRating <= 998))' .staging.result.json

# Explanation of the Addition:
# | map(select(.totalRuleRating == 1)): This part filters the array of objects to include only those where totalRuleRating equals 1. It's applied after aggregating the totalRuleRating for each ruleKey, ensuring that only rules meeting this specific criterion are listed in the final output.
# This command will now output a list of rules grouped by ruleKey with their aggregated totalRuleRating, but only those rules where the totalRuleRating is exactly 1 will be included in the results.

jq 'map(.warnings + .failures | select(. != null)[]) | group_by(.metadata.ruleKey) | map({ruleKey: .[0].metadata.ruleKey, totalRuleRating: map(.metadata.ruleRating) | add}) | map(select(.totalRuleRating == 1))' .staging.result.json

# Explanation of the Update:
# | map(select(.totalRuleRating &gt;= 2 and .totalRuleRating &lt;= 998)): This filter is applied to select only those entries where totalRuleRating is greater than or equal to 2 and less than or equal to 998. This ensures that the final output includes only the rules that meet this specific range criterion.
# This command effectively filters and lists rules based on the specified totalRuleRating range, providing a focused view of rules that are neither the lowest nor the highest in terms of risk or priority, as indicated by their rating.

jq 'map(.warnings + .failures | select(. != null)[]) | group_by(.metadata.ruleKey) | map({ruleKey: .[0].metadata.ruleKey, totalRuleRating: map(.metadata.ruleRating) | add}) | map(select(.totalRuleRating >= 2 and .totalRuleRating <= 998))' .staging.result.json


jq 'map(.warnings + .failures | select(. != null)[]) | group_by(.metadata.ruleKey) | map({ruleKey: .[0].metadata.ruleKey, totalRuleRating: map(.metadata.ruleRating) | add}) | map(select(.totalRuleRating >= 998))' .staging.result.json
```

jq '[
      (.warnings + .failures | select(. != null)[])
    ] | group_by(.metadata.ruleKey) | map({
      (. | .[0].metadata.ruleKey): {
        totalRuleRating: map(.metadata.ruleRating) | add,
        totalCount: length,
        ruleAction: .[0].metadata.ruleAction,
        network: .[0].metadata.network,
        project: .[0].metadata.project,
        ruleName: .[0].metadata.ruleName,
        direction: .[0].metadata.ruleDirection,
        rulePriority: .[0].metadata.rulePriority,
        violation_overview: map({message: .msg, namespace: .namespace, severity: .metadata.severity, ruleRating: .metadata.ruleRating})
      }
    }) | add' .staging.result.json

```shell
jq '[
  .[] | . as $root | 
  ($root.warnings // [] + $root.failures // [])[] | 
  {
    ruleKey: .metadata.ruleKey, 
    ruleRating: .metadata.ruleRating, 
    msg: .msg, 
    namespace: $root.namespace, 
    severity: .metadata.severity, 
    ruleAction: .metadata.ruleAction, 
    network: .metadata.network, 
    project: .metadata.project, 
    ruleName: .metadata.ruleName, 
    direction: .metadata.ruleDirection, 
    rulePriority: .metadata.rulePriority
  }
] | 
group_by(.ruleKey) | 
map({
  (.[0].ruleKey): {
    totalRuleRating: map(.ruleRating) | add, 
    totalCount: length, 
    ruleAction: .[0].ruleAction, 
    network: .[0].network, 
    project: .[0].project, 
    ruleName: .[0].ruleName, 
    direction: .[0].direction, 
    rulePriority: .[0].rulePriority, 
    violation_overview: map({
      message: .msg, 
      namespace: .namespace, 
      severity: .severity, 
      ruleRating: .ruleRating
    }| sort_by(.ruleRating))
  }
}) | 
add' .staging.result.json


jq '[
  .[] | . as $root | 
  ($root.warnings // [] + $root.failures // [])[] | 
  {
    ruleKey: .metadata.ruleKey, 
    ruleRating: .metadata.ruleRating, 
    msg: .msg, 
    namespace: $root.namespace, 
    severity: .metadata.severity, 
    ruleAction: .metadata.ruleAction, 
    network: .metadata.network, 
    project: .metadata.project, 
    ruleName: .metadata.ruleName, 
    direction: .metadata.ruleDirection, 
    rulePriority: .metadata.rulePriority
  }
]' .staging.result.json


```sh
jq '[.[] | . as $root | 
  ($root.warnings // [] + $root.failures // [])[] | 
  {
    ruleKey: .metadata.ruleKey, 
    ruleRating: .metadata.ruleRating, 
    msg: .msg, 
    namespace: $root.namespace, 
    severity: .metadata.severity, 
    ruleAction: .metadata.ruleAction, 
    network: .metadata.network, 
    project: .metadata.project, 
    ruleName: .metadata.ruleName, 
    direction: .metadata.ruleDirection, 
    rulePriority: .metadata.rulePriority
  }
] | 
group_by(.ruleKey) | 
map({
  (.[0].ruleKey): {
    totalRuleRating: map(.ruleRating) | add, 
    totalCount: length, 
    ruleAction: .[0].ruleAction, 
    network: .[0].network, 
    project: .[0].project, 
    ruleName: .[0].ruleName, 
    direction: .[0].direction, 
    rulePriority: .[0].rulePriority, 
    violation_overview: (map({
      message: .msg, 
      namespace: .namespace, 
      severity: .severity, 
      ruleRating: .ruleRating
    }) | sort_by(.ruleRating) | reverse)
  }
}) | 
add | to_entries | sort_by(.value.totalRuleRating) | reverse | from_entries' .staging.result.json

jq '[.[] | 
  . as $root | 
  ($root.warnings // [] + $root.failures // [])[] | 
  {
    ruleKey: .metadata.ruleKey, 
    ruleRating: .metadata.ruleRating, 
    msg: .msg, 
    action: .metadata.action,
    namespace: $root.namespace, 
    severity: .metadata.severity, 
    ruleAction: .metadata.ruleAction, 
    network: .metadata.network, 
    project: .metadata.project, 
    ruleName: .metadata.ruleName, 
    direction: .metadata.ruleDirection, 
    rulePriority: .metadata.rulePriority
  }
]' .staging.result.json > .staging.failures_list.json


jq 'group_by(.ruleKey) | 
  map({
    (.[0].ruleKey): {
      totalRuleRating: map(.ruleRating) | add, 
      totalCount: length, 
      ruleAction: .[0].ruleAction, 
      action: .[0].action, 
      network: .[0].network, 
      project: .[0].project, 
      ruleName: .[0].ruleName, 
      direction: .[0].direction, 
      rulePriority: .[0].rulePriority, 
      violation_overview: (map({
        message: .msg, 
        namespace: .namespace, 
        severity: .severity, 
        ruleRating: .ruleRating
      }) | sort_by(.ruleRating) | reverse)
    }
  }) | 
  add | to_entries | sort_by(.value.totalRuleRating) | reverse | 
  from_entries' .staging.failures_list.json > .staging.failures_grouped.json

jq '. | map(select(.totalRuleRating > 1))' .staging.failures_grouped.json

## Parse raw json to find file names of rules that were updated/delete
jq -r '.resource_changes[] | select(.name == "firewall_rules_map") | .change.after.content | fromjson' .staging.tfplan.json > .staging.firewall_rules_map.json

jq --slurpfile rulesMap .staging.firewall_rules_map.json '
  group_by(.ruleKey) | 
  map({
    (.[0].ruleKey): {
      totalRuleRating: map(.ruleRating) | add, 
      totalCount: length, 
      ruleAction: .[0].ruleAction, 
      action: .[0].action, 
      network: .[0].network, 
      project: .[0].project, 
      ruleName: .[0].ruleName, 
      direction: .[0].direction, 
      rulePriority: .[0].rulePriority, 
      violation_overview: (map({
        message: .msg, 
        namespace: .namespace, 
        severity: .severity, 
        ruleRating: .ruleRating
      }) | sort_by(.ruleRating) | reverse),
      environment: ($rulesMap[0][.][0].environment // "UNKNOWN"),
      prefix: ($rulesMap[0][.][0].prefix // "UNKNOWN"),
      file_name: ($rulesMap[0][.][0].file_name // "UNKNOWN"),
      id: ($rulesMap[0][.][0].id // "UNKNOWN")
    }
  }) | 
  add | to_entries | sort_by(.value.totalRuleRating) | reverse | 
  from_entries' .staging.failures_list.json > .staging.failures_grouped.json

  jq --slurpfile rulesMap .staging.firewall_rules_map.json '
  .[] | . as $item | 
  $rulesMap[] | select(.ruleKey == $item.ruleKey) | 
  {
    ruleKey: $item.ruleKey,
    environment: .environment,
    prefix: .prefix,
    file_name: .file_name,
    id: .id
  }
' .staging.failures_list.json

jq --slurpfile rulesMap .staging.firewall_rules_map.json '
  .[] | . as $item | 
  {
    ruleKey: $item.ruleKey,
    totalRuleRating: ($item.ruleRating | add),
    totalCount: length,
    ruleAction: $item.ruleAction,
    action: $item.action,
    network: $item.network,
    project: $item.project,
    ruleName: $item.ruleName,
    direction: $item.direction,
    rulePriority: $item.rulePriority,
    violation_overview: (map({
      message: .msg,
      namespace: .namespace,
      severity: .severity,
      ruleRating: .ruleRating
    }) | sort_by(.ruleRating) | reverse),
    fileName: ($rulesMap[0][$item.ruleKey].file_name)
  }
' .staging.failures_list.json > .staging.failures_grouped.json

jq --slurpfile rulesMap .staging.firewall_rules_map.json '
  map(
    . + {
      fileName: ($rulesMap[0][.ruleKey].file_name)
    }
  )
' .staging.failures_list.json

  jq --slurpfile rulesMap .staging.firewall_rules_map.json '.[] | . as $item | $rulesMap[] | select()'  .staging.failures_list.json
```