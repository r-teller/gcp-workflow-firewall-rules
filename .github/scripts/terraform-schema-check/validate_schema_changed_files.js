const Ajv = require("ajv");

module.exports = async ({ github, context, core }) => {
  const ajv = new Ajv({ allErrors: true, verbose: true });
  const changedFiles = JSON.parse(process.env.CHANGED_FILES);
  const validationErrors = [];

  // Load the schema
  const schemaPath =
    ".terraform/modules/firewall_rules/schemas/resolved/resolved.schema.json";
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
  const validate = ajv.compile(schema);

  for (const file of changedFiles) {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
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
        validationErrors.push(filteredErrors);
      }
    }
  }

  core.setOutput("validation_errors", JSON.stringify(validationErrors));
  console.log(JSON.stringify(validationErrors, null, 2));
  return validationErrors;
};
