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

Note on Fine-grained PAT's: at the time of writing (Jan 2023), those are in Beta state and do not yet support access to the GraphQL API (see [github/roadmap#622](https://github.com/github/roadmap/issues/622)). Therefore, a _classic_ token has to be used (prefix `ghp_` for classic versus `github_pat_` for fine-grained).
