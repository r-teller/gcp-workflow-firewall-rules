module.exports = async ({
  github,
  context,
  core,
  jsonSchemaValidationErrors,
}) => {
  //   const jsonSchemaValidationErrors = JSON.parse(core.getInput("jsonSchemaValidationErrors"));

  let commentBody = "### 🔴 Schema Validation Failed\n\n";
  commentBody += "The following files failed schema validation:\n\n";

  if (jsonSchemaValidationErrors.length > 0) {
    commentBody += "#### Schema Validation Errors:\n";
    jsonSchemaValidationErrors.forEach((error) => {
      commentBody += `- **File**: ${error.filename}\n`;
      error.errors.forEach((err) => {
        console.log(err.message);
        commentBody += `  - **Error**: ${JSON.stringify(err.message)}\n`;
      });
    });
  }

  await github.rest.issues.createComment({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: context.issue.number,
    body: commentBody,
  });
};
