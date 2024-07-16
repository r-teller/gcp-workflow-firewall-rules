const fs = require("fs");

module.exports = async ({ github, context, core }) => {
  const opaViolations = [];
  let criticalOpaViolationsDetected = false;

  core.setOutput("opaViolations", opaViolations);
  core.setOutput(
    "criticalOpaViolationsDetected",
    criticalOpaViolationsDetected
  );
};
