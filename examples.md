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
    .[$failure.metadata.ruleID] += [$failure.metadata.severity] | map_values(unique) | map_values(sort)
)' ./.staging.result.json

### Create a list of all rules and their severities
jq 'reduce (.[]?.failures[]?, .[]?.warnings[]?) as $item (
    {}; 
    .[$item.metadata.ruleID] += [$item.metadata.severity] | map_values(unique) | map_values(sort)
)' ./.staging.result.json
```

```shell
### List all rules that do not match anything other than CATCH_ALL
jq 'reduce (.[]?.failures[]?, .[]?.warnings[]?) as $item (
    {}; 
    .[$item.metadata.ruleID] += [$item.metadata.severity] | map_values(unique) | map_values(sort)
) | with_entries(select(.value | length == 1))' .staging.result.json


jq 'reduce (.[]?.failures[]?, .[]?.warnings[]?) as $item (
    {}; 
    .[$item.metadata.ruleID] += [$item.metadata.severity] | map_values(unique) | map_values(sort)
) | with_entries(select(.value | length == 1)) | keys[]' .staging.result.json | xargs -I {} jq '.resource_changes[] | select(.index == "{}") | .change.after' .staging.tfplan.json

```