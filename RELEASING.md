# Releasing OWASP Dependency-Track

This document describes the process of releasing a new version of Dependency-Track via GitHub Actions.

## Pre-Release Checklist

- [ ] Ensure that there is no dependency on `SNAPSHOT` versions of libraries and frameworks
- [ ] In case the release includes database schema changes or [upgrades](src/main/java/org/dependencytrack/upgrade), ensure that they work with all supported databases
  - [ ] Embedded H2
  - [ ] Microsoft SQL Server
  - [ ] MySQL
  - [ ] PostgreSQL
- [ ] Ensure that a [changelog](docs/_posts) entry for the release exists and is complete
- [ ] Bump the `version` field in [`docs/_config.yml`](docs/_config.yml) to the new version
- [ ] When API server and frontend shall be released together
  - [ ] Release the frontend first
  - [ ] Bump to the `frontend.version` property in `pom.xml` according to the new version

## Releasing

### Release a new major or minor version

1. Ensure the current state in `master` is ready to be released
2. Head over to the *Actions* tab in GitHub
3. Select the *Release CI* entry in the *Workflows* section
4. The following UI element will have a button to trigger the workflow. Once clicked, the *Use workflow from* dialog will appear:

![Create a release from `master`](./.github/images/release-master.png)

5. Ensure that `master` is selected in the branch dropdown
6. OPTIONAL. If the version you intend to release differs from the version in the branch you can overwrite it by specifying it in the input variable designated for it
7. Finally, once all inputs are checked press the *Run Workflow* button

### Release a new bugfix version

1. Ensure the current state in the release branch is ready to be released
2. Head over to the *Actions* tab in GitHub
3. Select the *Release CI* entry in the *Workflows* section
4. The following UI element will have a button to trigger the workflow. Once clicked, the *Use workflow from* dialog will appear:

![Create a release from a release branch](./.github/images/release-releasebranch.png)

5. Ensure that a release branch (e.g. `4.5.x`) is selected in the branch dropdown
6. OPTIONAL. If the version you intend to release differs from the version in the branch you can overwrite it by specifying it in the input variable designated for it
7. Finally, once all inputs are checked press the *Run Workflow* button

## Post-Release Checklist

- [ ] Collect hashes of all release artifacts (e.g. via `checksums.txt` attached to GitHub Releases)
  - [ ] API server: `dependency-track-apiserver.jar`, `dependency-track-bundled.jar`
  - [ ] frontend: `frontend-dist.zip`
- [ ] Collect links for all SBOMs generated during the release (they're attached to GitHub Releases)
- [ ] Create a branch from the latest release branch (e.g. `4.6.x`)
  - [ ] Update the release [changelog](docs/_posts) with the collected hashes and SBOMs
  - [ ] Create PR back into the release branch and get it merged
- [ ] Change the deployment branch for [GitHub Pages](https://github.com/DependencyTrack/dependency-track/settings/pages) to the new release branch
- [ ] Update *Dependency-Track Version* options in issue templates
  - [ ] [Defect Report](https://github.com/DependencyTrack/dependency-track/blob/master/.github/ISSUE_TEMPLATE/defect-report.yml)
  - [ ] [Enhancement Request](https://github.com/DependencyTrack/dependency-track/blob/master/.github/ISSUE_TEMPLATE/enhancement-request.yml)
