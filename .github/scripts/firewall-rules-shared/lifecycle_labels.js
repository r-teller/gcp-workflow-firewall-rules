/**
 * Function to manage labels on a pull request.
 * If remove_label_name is provided and assigned, it will be removed.
 * If add_label_name is provided and not already present, it will be added.
 *
 * @param {Object} github - The GitHub object provided by actions/github-script.
 * @param {Object} context - The context object provided by actions/github-script.
 * @param {string} [add_label_name] - The label to be added (optional).
 * @param {string} [remove_label_name] - The label to be removed (optional).
 */

module.exports = async ({ github, context, add_label_name = null, remove_label_name = null }) => {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const issue_number = context.issue.number;

  // Get the list of labels assigned to the pull request
  const { data: labels } = await github.rest.issues.listLabelsOnIssue({
    owner,
    repo,
    issue_number,
  });

  const labelNames = labels.map((label) => label.name);

  // Check if remove_label_name is provided and assigned
  if (remove_label_name && labelNames.includes(remove_label_name)) {
    // Remove the specified label
    await github.rest.issues.removeLabel({
      owner,
      repo,
      issue_number,
      name: remove_label_name,
    });
  }

  // Check if add_label_name is provided and not already present
  if (add_label_name && !labelNames.includes(add_label_name)) {
    // Add the new label
    await github.rest.issues.addLabels({
      owner,
      repo,
      issue_number,
      labels: [add_label_name],
    });
  }
};
