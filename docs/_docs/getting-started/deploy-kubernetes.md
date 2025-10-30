---
title: Deploying on Kubernetes
category: Getting Started
chapter: 1
order: 2
---

Kubernetes deployment is supported via [Helm]. Charts are maintained in the [helm-charts] repository.

To add the Helm repository:

```shell
helm repo add dependency-track https://dependencytrack.github.io/helm-charts
```

The following will deploy Dependency-Track as [release](https://helm.sh/docs/intro/cheatsheet/) `dtrack`
into the `dtrack` namespace, creating the namespace if it doesn't exist already:

```shell
helm install dtrack dependency-track/dependency-track \
    --namespace dtrack --create-namespace
```

For more details, such as available configuration options, please refer to [the chart's documentation].

Note that the chart does not include an external database such as PostgreSQL,
and instead defaults to an embedded H2 database. H2 is not intended for production
usage, please refer to the [database support] page for further information.

[the chart's documentation]: https://github.com/DependencyTrack/helm-charts/tree/main/charts/dependency-track
[database support]: {{ site.baseurl }}{% link _docs/getting-started/database-support.md %}
[Helm]: https://helm.sh/
[helm-charts]: https://github.com/DependencyTrack/helm-charts