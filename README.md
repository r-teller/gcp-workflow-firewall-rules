# gcp-workflow-firewall-rules

```bash
terraform plan -out=tfplan && terraform show -json ./tfplan > tfplan.json
docker run --rm -v $(pwd):/project openpolicyagent/conftest test --all-namespaces ./.staging.tfplan.json --output json > ./.staging.result.json

jq '.[] | .failures[]? | select(.metadata.severity != "LOW")' ./result.json

jq '.[] | .failures[]? | select(.metadata.severity == "LOW")' ./result.json


jq '.[] | .failures[]? | select(.metadata.severity == "CRITICAL")' ./result.json
```