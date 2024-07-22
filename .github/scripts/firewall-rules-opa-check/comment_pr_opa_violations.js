module.exports = async ({ github, context, core, opaViolations }) => {
  const commentId = `${context.issue.number}-${github.run_id}-${github.run_attempt}`;

  let detailedMessages = "#### Detailed Messages:\n\n" + "| # | Details |\n" + "|---|---------|\n";

  const tableHeader = "| # | Action |  Rule Name | Rule Action | Rule Rating | Violation Count | Severity Indicator |\n";
  const tableSeparator = "| --- | --- | --- | --- | --- | --- | --- |\n";
  const tableRows = [];
  // console.log(opaViolations);
  let index = 0;
  for (const key in opaViolations) {
    const {
      violationIndex = index + 1,
      action = "N/A",
      ruleName = "N/A",
      ruleAction = "N/A",
      direction = "N/A",
      rulePriority = "N/A",
      totalCount = "N/A",
      totalRuleRating,
      project = "N/A",
      network = "N/A",
      fileName = "N/A",
      ruleIndex = "N/A",
      environment = "N/A",
      prefix = "N/A",
      ruleId = "N/A",
      violationOverview = [],
    } = opaViolations[key];

    let severityIndicator = "🔴"; // Default to red circle

    if (totalRuleRating === 1) {
      severityIndicator = "✅"; // Green check for totalRuleRating == 1
    } else if (totalRuleRating > 1 && totalRuleRating < 999) {
      severityIndicator = "⚠️"; // Yellow caution sign for totalRuleRating > 1 & < 999
    }

    tableRows.push(`| ${violationIndex} | ${action} | ${ruleName} | ${ruleAction} | ${totalRuleRating} | ${totalCount} | ${severityIndicator} |`);

    let details =
      `**Action**: ${action}<br>` +
      `**Rule Name**: ${ruleName}<br>` +
      `**Rule Action**: ${ruleAction}<br>` +
      `**Rule Direction**: ${direction}<br>` +
      `**Rule Priority**: ${rulePriority}<br>` +
      `**Rule ID**: ${ruleId}<br>` +
      `**Project**: ${project}<br>` +
      `**Network**: ${network}<br>` +
      `**File Name**: ${fileName}<br>` +
      `**Rule Index**: ${ruleIndex}<br>` +
      `**Environment**: ${environment}<br>` +
      `**Prefix**: ${prefix}<br>` +
      `**Violation Overview**:<br>` +
      violationOverview
        .map((violation) => {
          return (
            `<hr>` +
            `&bull; **Message**: ${violation.message ?? "N/A"}<br>` +
            `&bull; **Namespace**: ${violation.namespace ?? "N/A"}<br>` +
            `&bull; **Severity**: ${violation.severity ?? "N/A"}<br>` +
            `&bull; **Rule Rating**: ${violation.ruleRating ?? "N/A"}`
          );
        })
        .join("<br>");

    detailedMessages += `| ${violationIndex} | ${details} |\n`;
    index++;
  }

  const highestTotalRuleRating = Math.max(...Object.values(opaViolations).map((issue) => issue.totalRuleRating));
  let commentIcon = "🔴"; // Default to red circle
  if (highestTotalRuleRating === 1) {
    commentIcon = "✅"; // Green check for totalRuleRating == 1
  } else if (highestTotalRuleRating > 1 && highestTotalRuleRating < 999) {
    commentIcon = "⚠️"; // Yellow caution sign for totalRuleRating > 1 & < 999
  }

  const commentBody = `### ${commentIcon} -- Pull Request Risk Matrix\n\n${tableHeader}${tableSeparator}${tableRows.join("\n")}\n\n${detailedMessages}`;

  await github.rest.issues.createComment({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: context.issue.number,
    body: commentBody,
  });
};
