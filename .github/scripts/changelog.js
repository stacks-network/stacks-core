module.exports = async ({ github, context, core }) => {
  if (context.eventName !== "pull_request") {
    core.info(
      `Event is '${context.eventName}', not a pull request — skipping.`
    );
    return;
  }
  // Fetch current labels (payload labels are stale on re-runs)
  const { data: pr } = await github.rest.pulls.get({
    owner: context.repo.owner,
    repo: context.repo.repo,
    pull_number: context.issue.number,
  });
  const labels = pr.labels.map((l) => l.name);
  if (labels.includes("no changelog")) {
    core.info('PR has "no changelog" label — skipping changelog check.');
    return;
  }

  const { data: files } = await github.rest.pulls.listFiles({
    owner: context.repo.owner,
    repo: context.repo.repo,
    pull_number: context.issue.number,
    per_page: 100,
  });

  // Fail if CHANGELOG.md is modified directly
  const directEdits = files.filter(
    (f) => f.filename === "CHANGELOG.md" && f.status === "modified"
  );

  if (directEdits.length > 0) {
    core.setFailed(
      "Do not edit CHANGELOG.md directly. " +
        "Add a changelog fragment to changelog.d/ instead " +
        "(see changelog.d/README.md for instructions)."
    );
    return;
  }

  // stacks-signer/CHANGELOG.md is a frozen historical record
  const signerEdits = files.filter(
    (f) => f.filename === "stacks-signer/CHANGELOG.md"
  );

  if (signerEdits.length > 0) {
    core.setFailed(
      "stacks-signer/CHANGELOG.md is a frozen historical record. " +
        "Signer changes now go in the root CHANGELOG.md via fragments in " +
        "changelog.d/ (see changelog.d/README.md for instructions)."
    );
    return;
  }

  // stacks-signer/changelog.d/ is retired; all fragments go in the root changelog.d/
  const signerFragments = files.filter(
    (f) =>
      f.filename.startsWith("stacks-signer/changelog.d/") &&
      f.status !== "removed"
  );

  if (signerFragments.length > 0) {
    const names = signerFragments.map((f) => f.filename).join(", ");
    core.setFailed(
      `Changelog fragment(s) found in the retired stacks-signer/changelog.d/ directory: ${names}. ` +
        "Signer changes now use the root changelog.d/ directory " +
        "(see changelog.d/README.md for instructions)."
    );
    return;
  }

  const validExtensions = [
    "breaking",
    "added",
    "changed",
    "fixed",
    "removed",
  ];
  const fragments = files.filter(
    (f) =>
      f.filename.startsWith("changelog.d/") &&
      f.status === "added" &&
      validExtensions.some((ext) => f.filename.endsWith(`.${ext}`))
  );

  if (fragments.length === 0) {
    core.setFailed(
      "No changelog fragment found. Please add a fragment file to changelog.d/ " +
        "(see changelog.d/README.md for instructions). " +
        'If no changelog entry is needed, add the "no changelog" label to the PR.'
    );
  } else {
    const names = fragments.map((f) => f.filename).join(", ");
    core.info(`Found changelog fragment(s): ${names}`);
  }
};
