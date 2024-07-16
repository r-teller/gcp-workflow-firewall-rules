module.exports = async ({ github, context, core }) => {
  // Define the list of path prefixes you want to filter by
  const pathPrefixes = [
    // Add more prefixes as needed
    "rules/",
  ];

  // Define the list of file extensions you want to include
  const allowedExtensions = [
    // Add more extensions as needed
    ".json",
  ];

  const payload = context.payload.pull_request;

  try {
    const { data: diff } = await github.rest.pulls.listFiles({
      owner: context.repo.owner,
      repo: context.repo.repo,
      pull_number: payload.number,
    });

    const changedFiles = diff
      .map((file) => file.filename)
      .filter(
        (file) =>
          allowedExtensions.some((ext) => file.endsWith(ext)) &&
          pathPrefixes.some((prefix) => file.startsWith(prefix))
      );
    console.log(changedFiles);
    core.setOutput("changedFiles", changedFiles);
    // return changedFiles;
  } catch (error) {
    core.setFailed(`Error getting changed files: ${error.message}`);
  }
};
