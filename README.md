[![Build Status](https://github.com/DependencyTrack/dependency-track/workflows/CI%20Build/badge.svg)](https://github.com/DependencyTrack/dependency-track/actions?workflow=CI+Build)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b2ecd06dab57438a9a55bc4a71c5a8ce)](https://www.codacy.com/gh/DependencyTrack/dependency-track/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=DependencyTrack/dependency-track&amp;utm_campaign=Badge_Grade)
[![Alpine](https://img.shields.io/badge/built%20on-Alpine-blue.svg)](https://github.com/stevespringett/Alpine)
[![License][license-image]][Apache License 2.0]
[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-orange.svg)](https://www.owasp.org/index.php/OWASP_Dependency_Track_Project)
[![Website](https://img.shields.io/badge/https://-dependencytrack.org-blue.svg)](https://dependencytrack.org/)
[![Documentation](https://img.shields.io/badge/read-documentation-blue.svg)](https://docs.dependencytrack.org/)
[![Slack](https://img.shields.io/badge/chat%20on-slack-46BC99.svg)](https://dependencytrack.org/slack)
[![Group Discussion](https://img.shields.io/badge/discussion-groups.io-blue.svg)](https://dependencytrack.org/discussion)
[![YouTube Subscribe](https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg)](https://dependencytrack.org/youtube)
[![Twitter](https://img.shields.io/twitter/follow/dependencytrack.svg?label=Follow&style=social)](https://twitter.com/dependencytrack)
[![Downloads](https://img.shields.io/github/downloads/DependencyTrack/dependency-track/total.svg)](https://github.com/DependencyTrack/dependency-track/releases)
[![Latest](https://img.shields.io/github/release/DependencyTrack/dependency-track.svg)](https://github.com/DependencyTrack/dependency-track/releases)
[![Pulls - API Server](https://img.shields.io/docker/pulls/dependencytrack/apiserver.svg?label=Docker%20Pulls%20%28API%20Server%29)](https://hub.docker.com/r/dependencytrack/apiserver/)
[![Pulls - Frontend](https://img.shields.io/docker/pulls/dependencytrack/frontend.svg?label=Docker%20Pulls%20%28Frontend%29)](https://hub.docker.com/r/dependencytrack/frontend/)
[![Pulls - Bundled](https://img.shields.io/docker/pulls/dependencytrack/bundled.svg?label=Docker%20Pulls%20%28Bundled%29)](https://hub.docker.com/r/dependencytrack/bundled/)
[![Pulls - Legacy](https://img.shields.io/docker/pulls/owasp/dependency-track.svg?label=Docker%20Pulls%20%28OWASP%20Legacy%29)](https://hub.docker.com/r/owasp/dependency-track/)

![logo preview](https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo.svg?sanitize=true)


Dependency-Track is an intelligent [Component Analysis] platform that allows organizations to
identify and reduce risk in the software supply chain. Dependency-Track takes a unique
and highly beneficial approach by leveraging the capabilities of [Software Bill of Materials] (SBOM). This approach
provides capabilities that traditional Software Composition Analysis (SCA) solutions cannot achieve.

Dependency-Track monitors component usage across all versions of every application in its portfolio in order to
proactively identify risk across an organization. The platform has an API-first design and is ideal for use in
CI/CD environments.

---

Steps to deploy your own DependencyTrack instance instrumented with Segment:
1. Make changes in the code to add segment analytics.
2. Build the projects using 
```mvn clean package -P clean-exclude-wars -P enhance -P embedded-jetty -DskipTests -Dlogback.configuration.file=src/main/docker/logback.xml -e```
3. Build a new docker image: ```docker build -t instrumented-dtrack-v1 -f src/main/docker/Dockerfile .```
4. Update the `docker-compose.yml` file with latest image name.
5. Insert the value for `SYSTEM_SEGMENT_WRITE_KEY` environment variable