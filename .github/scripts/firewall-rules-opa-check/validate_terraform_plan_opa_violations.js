const fs = require("fs");

module.exports = async ({ github, context, core }) => {
  const opaViolations = [];
  let criticalOpaViolationsDetected = false;

  // Read the result.json file
  // This file contains the results of the Conftest policy checks.
  const resultJson = fs.readFileSync("./result.json", "utf8");
  const result = JSON.parse(resultJson);

  // Process the JSON data and format it into the desired structure for each violation
  // Combine warnings and failures into a single list of violations.
  const failuresList = result.flatMap((root) => {
    const combined = [...(root.warnings ?? []), ...(root.failures ?? [])];
    return combined.map((item) => ({
      ruleKey: item.metadata.ruleKey,
      ruleRating: item.metadata.ruleRating,
      msg: item.msg,
      action: item.metadata.action,
      namespace: root.namespace,
      severity: item.metadata.severity,
      ruleAction: item.metadata.ruleAction,
      network: item.metadata.network,
      project: item.metadata.project,
      ruleName: item.metadata.ruleName,
      direction: item.metadata.ruleDirection,
      rulePriority: item.metadata.rulePriority,
    }));
  });

  // Extract the content of the 'firewall_rules_map' resource from the Terraform plan JSON output
  // This map contains metadata about the firewall rules that are being managed by Terraform.
  const tfplanJson = fs.readFileSync("./tfplan.json", "utf8");
  const tfplan = JSON.parse(tfplanJson);
  const firewallRulesMap = tfplan.resource_changes.filter((change) => change.name === "firewall_rules_map").map((change) => JSON.parse(change.change.after.content))[0];

  // Group the data by ruleKey and calculate the totalRuleRating
  // This step aggregates the violations by ruleKey and calculates the total rating for each rule.
  const groupedFailures = failuresList.reduce((acc, item) => {
    if (!acc[item.ruleKey]) {
      acc[item.ruleKey] = {
        totalRuleRating: 0,
        totalCount: 0,
        ruleAction: item.ruleAction,
        fileName: firewallRulesMap[item.ruleKey]?.file_name || "UNKNOWN",
        ruleIndex: firewallRulesMap[item.ruleKey]?.rule_index || "UNKNOWN",
        ruleId: firewallRulesMap[item.ruleKey]?.id || "UNKNOWN",
        environment: firewallRulesMap[item.ruleKey]?.environment || "UNKNOWN",
        prefix: firewallRulesMap[item.ruleKey]?.prefix || "UNKNOWN",
        action: item.action,
        network: item.network,
        project: item.project,
        ruleName: item.ruleName,
        direction: item.direction,
        rulePriority: item.rulePriority,
        violationOverview: [],
      };
    }
    acc[item.ruleKey].totalRuleRating += item.ruleRating;
    acc[item.ruleKey].totalCount += 1;
    acc[item.ruleKey].violationOverview.push({
      message: item.msg,
      namespace: item.namespace,
      severity: item.severity,
      ruleRating: item.ruleRating,
    });
    return acc;
  }, {});

  // Sort the rules by totalRuleRating from high to low
  // This ensures that the most critical violations are listed first.
  const sortedFailures = Object.entries(groupedFailures)
    .sort((a, b) => b[1].totalRuleRating - a[1].totalRuleRating)
    .reduce((acc, [key, value]) => {
      acc[key] = value;
      return acc;
    }, {});

  // Check for non-low severity issues
  // If there are any violations with a totalRuleRating other than 1, we flag it as critical.
  const nonLowFailureCount = Object.values(sortedFailures).filter((item) => item.totalRuleRating !== 1).length;

  if (nonLowFailureCount > 0) {
    criticalOpaViolationsDetected = true;
  }

  // Set the outputs for the GitHub Action
  core.setOutput("opaViolations", sortedFailures);
  core.setOutput("criticalOpaViolationsDetected", criticalOpaViolationsDetected);
};
