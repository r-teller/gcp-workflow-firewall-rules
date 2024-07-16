const fs = require("fs");
const Ajv = require("ajv");

module.exports = async ({ github, context, core, changedFiles }) => {
  const ajv = new Ajv({ allErrors: true, verbose: true });
  //   const changedFiles = JSON.parse(process.env.CHANGED_FILES);

  const jsonSchemaValidationErrors = [];
  const jsonLintErrors = [];
  const badFiles = [];

  // Load the schema
  const jsonSchemaPath =
    ".terraform/modules/firewall_rules/schemas/resolved/resolved.schema.json";
  const jsonSchema = JSON.parse(fs.readFileSync(jsonSchemaPath, "utf8"));
  const validate = ajv.compile(jsonSchema);

  for (const file of changedFiles) {
    const jsonString = fs.readFileSync(file, "utf8");
    let data;
    try {
      data = JSON.parse(jsonString);
    } catch (error) {
      jsonLintErrors.push({
        filename: file,
        error: `Syntax error: ${error.message}`,
      });
      badFiles.push(file);
      continue;
    }
    const valid = validate(data);

    if (!valid) {
      const filteredErrors = {
        filename: file,
        errors: validate.errors
          .filter(
            (e) =>
              e.params &&
              typeof e.params === "object" &&
              "passingSchemas" in e.params
          )
          .map(({ parentSchema, ...rest }) => rest),
      };

      if (filteredErrors.errors.length > 0) {
        jsonSchemaValidationErrors.push(filteredErrors);
      }
    }
  }

  core.setOutput("json_schema_validation_errors", JSON.stringify(jsonSchemaValidationErrors));
  core.setOutput("json_lint_errors", JSON.stringify(jsonLintErrors));
  core.setOutput("bad_files", JSON.stringify(badFiles));
};
