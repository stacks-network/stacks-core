# Contributing to Blockstack Core

Looking to contribute something to Blockstack Core? **Here's how you can help.**

Please take a moment to review this document in order to make the contribution process easy and effective for everyone in the community.

Following these guidelines helps to communicate that you respect the time of everyone involved in the Blockstack open source community. In return, the community will address your issue or assess patches and features as quickly as possible.

## Table of contents

- [Finding opportunities to contribute](#finding-opportunities-to-contribute)
- [Using the issue tracker](#using-the-issue-tracker)
- [Bug reports](#bug-reports)
- [Feature requests](#feature-requests)
- [Pull requests](#pull-requests)
- [Code guidelines](#code-guidelines)
- [Maintainers](#maintainers)
- [License](#license)

## Finding opportunities to contribute

There are two common ways to find opportunities to contribute:

- [Project Boards](https://github.com/blockstack/blockstack-core/projects)
- [Issue Tracker](https://github.com/blockstack/blockstack-core/issues)

The project boards is a great place to start. Look for the version that has the label `current`
and look for a ticket in the `To Do` column. Click on the ticket your interested in
and this will link you to the relative issue in the tracker.

If the ticket your interested in is being worked, feel free to provide feedback.

Otherwise, leave a comment addressing one of the [repo maintainers](#maintainers) to get
the conversation started.

Whether you are a veteran programmer, beginner programmer, or don't program at all, we
are positive you will find a place to helping us build a decentralized internet!

[Just Ask!](http://chat.blockstack.org/)

[^ Back To The Top](#contributing-to-blockstackorg)

## Using the issue tracker

The [issue tracker](https://github.com/blockstack/blockstack-core/issues) is the preferred channel for [bug reports](#bug-reports), [features requests](#feature-requests) and [submitting pull requests](#pull-requests), but please respect the following
restrictions:

* Please **do not** use the issue tracker for personal support requests.  Please use the [Forum](https://forum.blockstack.org) or [Slack](http://chat.blockstack.org) as they are better places to get help.

* Please **do not** derail or troll issues. Keep the discussion on topic and respect the opinions of others.

### Issues and labels

Our bug tracker utilizes several labels to help organize and identify issues.

For a complete look at our labels, see the [project labels page](https://github.com/blockstack/blockstack-core/labels).

[^ Back To The Top](#contributing-to-blockstackorg)

## Bug reports

A bug is a _demonstrable problem_ that is caused by the code in the repository. Good bug reports are extremely helpful, so thanks!

Guidelines for bug reports:

1. **Use the GitHub issue search** &mdash; [Search for duplicate or closed issues](https://github.com/blockstack/blockstack-core/issues?utf8=%E2%9C%93&q=is%3Aissue).

2. **Check if the issue has been fixed** &mdash; try to reproduce it using the latest `master`, `design` or development branch in the repository.

3. **Isolate the problem** &mdash; ideally create a [reduced test case](https://css-tricks.com/reduced-test-cases/) and a live example. [This JS Bin](https://jsbin.com/lolome/edit?html,output) is a helpful template. At the minimum, include steps one can take to reproduce the bug.

4. **Include Browser and Version** (Chrome, Firefox, Safari, IE, MS Edge, Opera 15+, Android Browser).

5. **Include Operating System and Version**

A good bug report shouldn't leave others needing to chase you up for more information. Please try to be as detailed as possible in your report. What is your environment? What steps will reproduce the issue? What browser(s) and OS experience the problem? Do other browsers show the bug differently? What would you expect to be the outcome? All these details will help people to fix any potential bugs.

Example:

> Short and descriptive example bug report title
>
> A summary of the issue and the browser/OS environment in which it occurs. If
> suitable, include the steps required to reproduce the bug.
>
> 1. This is the first step
> 2. This is the second step
> 3. Further steps, etc.
>
> `<url>` - a link to the reduced test case
>
> Any other information you want to share that is relevant to the issue being
> reported. This might include the lines of code that you have identified as
> causing the bug, and potential solutions (and your opinions on their
> merits).

[^ Back To The Top](#table-of-contents)

## Feature requests

Feature requests are welcome. But take a moment to find out whether your idea fits with the scope and aims of the project. It's up to *you* to make a strong case to convince the project's developers of the merits of this feature. Please provide as much detail and context as possible, providing relevant links, prior art, or live demos whenever possible.

[^ Back To The Top](#contributing-to-blockstackorg)

## Pull requests

**Working on your first Pull Request?** You can learn how from this *free* series [How to Contribute to an Open Source Project on GitHub](https://egghead.io/series/how-to-contribute-to-an-open-source-project-on-github)

Good pull requests—patches, improvements, new features—are a fantastic help. They should remain focused in scope and avoid containing unrelated commits.

**Please ask first** before embarking on any significant pull request (e.g. implementing features, refactoring code, porting to a different language), otherwise you risk spending a lot of time working on something that the project's developers might not want to merge into the project.

Ensure that your pull requests are small components. This assists both with your pull request getting accepted and makes it much easier/faster for the repository maintainer to merge in your pull request.

Please adhere to the [Blockstack Brand Guide](https://github.com/blockstack/designs/issues/247), [coding guidelines](#code-guidelines) used throughout the project (indentation, accurate comments, etc.), and any other requirements (such as test coverage).

Adhering to the following process is the best way to get your work included in the project:

1. [Fork](https://help.github.com/fork-a-repo/) the project, clone your fork,
   and configure the remotes:

   ```bash
   # Clone your fork of the repo into the current directory
   git clone https://github.com/<your-username>/blockstack-core.git
   # Navigate to the newly cloned directory
   cd blockstack-core
   # Assign the original repo to a remote called "upstream"
   git remote add upstream https://github.com/blockstack/blockstack-core.git
   ```

2. If you cloned a while ago, get the latest changes from the development branch upstream.

   ```bash
   git checkout -b develop
   git pull upstream develop
   ```

3. Set up a feature branch. *Keep the feature name short yet descriptive to the issue*

   ```bash
   git checkout -b <feature-branch-name>
   ```

4. Commit your changes in logical chunks. Please adhere to these [git commit
   message guidelines](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)
   or your code is unlikely be merged into the main project. Use Git's
   [interactive rebase](https://help.github.com/articles/interactive-rebase)
   feature to tidy up your commits before making them public.

   We advise including the issue number in the commit message as well.

5. Locally merge the upstream development branch into your topic branch:

   ```bash
   git pull upstream develop
   ```

6. Push your topic branch up to your fork:

   ```bash
   git push origin <feature-branch-name>
   ```

7. [Open a Pull Request](https://help.github.com/articles/using-pull-requests/) against the `develop` branch.
    - Add a clear title and description
    - Include screenshots of the before and after if your changes include differences in HTML/CSS. Drag and drop the images into the body of your pull request.
    - Reference any relevant issues or supporting documentation in your PR (ex. “Closes #37.”)
    - Make sure submitted code has no conflicts
    - Review your PR code to ensure there is no extra edits than required to resolve the issue. For example no additional refactoring, no extra lines of code, no irrelavent bug fixes.

**IMPORTANT**: By submitting a patch, you agree to allow the project owners to
license your work under the terms of the [MPL-2.0 License](https://github.com/blockstack/blockstack-browser/blob/master/LICENSE.md) (if it
includes code changes) and under the terms of the
[Creative Commons Attribution 3.0 Unported License](docs/LICENSE.md)
(if it includes documentation changes).

[^ Back To The Top](#contributing-to-blockstackorg)

## Code guidelines

### Integration Tests

Your PR shouldn't break any of the integration tests. See the `integration_tests` folder for more information on that.

[^ Back To The Top](#contributing-to-blockstackorg)

## Maintainers

<table>
  <tbody>
    <tr>
      <th>Maintainer</th>
      <th>Github</th>
    </tr>
    <tr>
      <td align="center">
        Muneeb Ali
      </td>
      <td align="center">
        <a href="https://github.com/muneeb-ali">muneeb-ali</a>
      </td>
    </tr>
    <tr>
      <td align="center">
        Aaron Blankstein
      </td>
      <td align="center">
        <a href="https://github.com/kantai">kantai</a>
      </td>
    </tr>
    <tr>
      <td align="center">
        Jude Nelson
      </td>
      <td align="center">
        <a href="https://github.com/jcnelson">jcnelson</a>
      </td>
    </tr>
  </tbody>
</table>

[^ Back To The Top](#contributing-to-blockstackorg)

## License

By contributing your code, you agree to license your contribution under the [MPL-2.0 License](https://github.com/blockstack/blockstack-core/blob/master/LICENSE.md).
