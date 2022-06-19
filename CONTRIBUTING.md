# Contributing to OWASP Dependency-Track

Thank you for contributing to Dependency-Track! We appreciate and are thankful for contributions in all shapes and sizes.

## Asking Questions

* Use either Slack or GitHub Discussions to ask questions.
* Do not open issues for questions. **Questions submitted through GitHub issues will be closed**.
* Consult the [community-maintained FAQ](https://docs.dependencytrack.org/FAQ/) to see whether your question has already been answered.
* Avoid contacting individual contributors directly; ask questions in public instead. A well-worded question will help serve as a resource to others searching for help.

The [`#proj-dependency-track` channel](https://dependencytrack.org/slack) in the OWASP Slack space is the best place 
to ask questions and get in touch with other users and contributors. We provide an invitation to the Slack space 
[here](https://dependencytrack.org/slack/invite). Please *do* create an issue if either channel link or invitation 
do not work anymore.

## Filing Issues

### Looking for existing Issues

Before you create a new issue, please do a search in [open issues](https://github.com/DependencyTrack/dependency-track/issues?q=is%3Aissue+is%3Aopen+) 
to see if the defect or enhancement request has already been filed.

If you find your issue already exists, add relevant comments to the existing issue. 

Optionally indicate your interest by reacting with *thumbs up* (👍). Issues with higher community attention are more likely to be addressed sooner.

If you cannot find an existing issue for your bug or feature request, create a new issue using the guidelines below.

### Requesting Enhancements

File a single issue per enhancement request. Do not list multiple enhancement requests in the same issue.

Describe your use case and the value you will get from the requested enhancement.

### Reporting Defects

File a single issue per defect. Do not list multiple defects in the same issue.

The more information you can provide, the more likely we will be successful at reproducing the bug and finding a fix.

Please include the following with each bug report:

* The Dependency-Track version you are using (for both API server and frontend)
* The Dependency-Track [distribution](https://github.com/DependencyTrack/dependency-track#distributions) you are using
* The database you are using
* Your operating system and version
* What you expected, versus what happened
* Reproducible steps (1 2 3...) that cause the defect including any required files
* Any relevant screenshots and other outputs

API server logs (including errors) are logged to the following locations per default:

* `~/.dependency-track/dependency-track.log` (`/data/.dependency-track/dependency-track.log` within Docker containers)
* Standard output (use `docker logs -f <CONTAINER_NAME>` when using Docker)

Errors in the frontend are logged to your browser's developer console (see [here](https://developer.chrome.com/docs/devtools/console/log/#browser) 
for Google Chrome). Issues in the communication between frontend and API server will be visible in the *Network* tab of 
your browser's developer tools (see [here](https://developer.chrome.com/docs/devtools/network/#load) for Google Chrome).

Depending on the defect, we may ask you for a sample BOM that triggers your issue.

Before sharing BOMs, logs, screenshots or any other resources with us, please ensure that you blank, pseudonymise or
remove all references that may leak internals of your organization.

## Reporting Vulnerabilities

Please refer to our security policy in [`SECURITY.md`](./SECURITY.md) for how to responsibly disclose vulnerabilities to us.

## Improving Documentation

Beside extending existing documentation or correcting any errors it may contain, another great way to contribute is to
update the [FAQ](https://docs.dependencytrack.org/FAQ/) with questions and answers that benefit the community.

Refer to the *Documentation* section of [`DEVELOPING.md`](./DEVELOPING.md) for a guide on how to build the documentation locally.

## Testing Snapshot Versions

Every time a commit is pushed to the `master` branch, container images are built and published to the `snapshot` tag.
This is true for both API server and frontend:

* [`dependencytrack/apiserver:snapshot`](https://hub.docker.com/r/dependencytrack/apiserver/tags?name=snapshot)
* [`dependencytrack/bundled:snapshot`](https://hub.docker.com/r/dependencytrack/bundled/tags?name=snapshot)
* [`dependencytrack/frontend:snapshot`](https://hub.docker.com/r/dependencytrack/frontend/tags?name=snapshot)

Testing `snapshot` versions and providing early feedback helps in improving the quality of new releases.
The private `#proj-dependency-track-beta` Slack channel is intended for discussions about and feedback for `snapshot`
versions. If you are interested in participating, please let us know in [`#proj-dependency-track`](https://dependencytrack.org/slack).

## Contributing Code

Before raising pull requests, please [file a defect](#reporting-defects) or [enhancement request](#requesting-enhancements) first. 

* We use [GitHub milestones](https://github.com/DependencyTrack/dependency-track/milestones) to plan what will be included in the next release. 
  * Depending on the size of your PR and whether it introduces breaking changes, we may schedule your change for a later release.
* Issues for which community contributions are explicitly requested are labeled with [`help wanted`](https://github.com/DependencyTrack/dependency-track/issues?q=is%3Aopen+label%3A%22help+wanted%22+).
* Issues suitable for first-time contributors are labeled with [`good first issue`](https://github.com/DependencyTrack/dependency-track/issues?q=is%3Aopen+label%3A%22good+first+issue%22+).

[`DEVELOPING.md`](./DEVELOPING.md) provides a detailed guide on how to get started with working on Dependency-Track.

### Pull Requests

* Pull requests that do not merge easily with the tip of the `master` branch will be declined.
  * The author will be asked to merge with tip and submit a new pull request.
* Code should follow standard code style conventions for whitespace, indentation and naming.
  * In the case of style differences between existing code and language standards, consistency with existing code is preferred.
* New functionality should have corresponding tests added to the existing test suite if possible.
* Avoid new dependencies if the functionality that is being used is trivial to implement directly or is available in standard libraries.
* Avoid checking in unrelated whitespace changes with code changes.
* Commits must be [signed off](https://git-scm.com/docs/git-commit#Documentation/git-commit.txt--s) to indicate agreement with [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
* Optionally include visualizations like screenshots, videos or [diagrams](https://github.blog/2022-02-14-include-diagrams-markdown-files-mermaid/) in the pull request description.

### Commit Messages

Please follow these rules when writing a commit message:

* Separate subject from body with a blank line
* Limit the subject line to 50 characters
* Capitalize the subject line
* Do not end the subject line with a period
* Use the imperative mood in the subject line
* Wrap the body at 72 characters
* Use the body to explain *what* and *why* vs. *how*
