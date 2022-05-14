---
title: GitHub Advisories
category: Datasources
chapter: 4
order: 2
redirect_from:
  - /datasources/nsp/
  - /datasources/npm/
---

[GitHub Advisories](https://github.com/advisories) (GHSA) is a database of CVEs and GitHub-originated security advisories affecting the open source world.
Advisories may or may not be documented in the [National Vulnerability Database]({{ site.baseurl }}{% link _docs/datasources/nvd.md %}).

Dependency-Track integrates with GHSA by mirroring advisories via GitHub's [public GraphQL API](https://docs.github.com/en/graphql).
The mirror is refreshed daily, or upon restart of the Dependency-Track instance.
A personal access token (PAT) is required in order to authenticate with GitHub, but no scopes have to be assigned to it.
GitHub provides guidance on how to create a PAT [here](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token).