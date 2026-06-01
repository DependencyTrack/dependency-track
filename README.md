# OWASP Dependency-Track

Dependency-Track is an intelligent Component Analysis platform that allows organizations to identify and reduce risk
in the software supply chain. Dependency-Track takes a unique and highly beneficial approach by leveraging the
capabilities of Software Bill of Materials (SBOM).

[![Build Status](https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-build.yaml/badge.svg)](https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-build.yaml)
[![Test Status](https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-test.yaml/badge.svg)](https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-test.yaml)
[![E2E Test Status](https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-test-e2e.yaml/badge.svg)](https://github.com/DependencyTrack/dependency-track/actions/workflows/ci-test-e2e.yaml)
[![Documentation](https://img.shields.io/badge/docs-next-blue.svg)](https://dependencytrack.github.io/docs/next/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.txt)

> [!WARNING]
> **Dependency-Track v5 is currently in release candidate stage and not yet generally available.**
>
> v5 release candidates are published for testing and feedback. They are not
> recommended for production deployments. The release candidate images are
> tagged `5.0.0-rc.<N>` and are not pulled by `:5-snapshot`.
>
> For production use, stay on the latest [v4 release](https://github.com/DependencyTrack/dependency-track/releases?q=4.).

> [!IMPORTANT]
> **Looking for Dependency-Track v4?**
> * v4 is in maintenance mode on the [`4.14.x` branch](https://github.com/DependencyTrack/dependency-track/tree/4.14.x).
> * v4 documentation: https://docs.dependencytrack.org/.
> * Migrating from v4 to v5? See [V5_MIGRATION.md](./V5_MIGRATION.md).
> * v4 will reach end-of-life *~6 months* after v5 GA.

## Documentation

User-facing documentation is rendered at [dependencytrack.github.io/docs/next](https://dependencytrack.github.io/docs/next/) and maintained in the [docs](https://github.com/DependencyTrack/docs) repository.

## Contributing

1. [Code of conduct](CODE_OF_CONDUCT.md)
2. [Contribution guidelines](CONTRIBUTING.md)
3. [Developer guide](DEVELOPING.md)

## See also

* [frontend](https://github.com/DependencyTrack/frontend): Frontend repository
* [docs](https://github.com/DependencyTrack/docs): Documentation repository
* [helm-charts](https://github.com/DependencyTrack/helm-charts): [Helm](https://helm.sh/) charts
* [community](https://github.com/DependencyTrack/community): Community resources
