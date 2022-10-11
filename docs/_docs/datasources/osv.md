---
title: Open Source Vulnerabilities
category: Datasources
chapter: 4
order: 3
---

> **Notice**
>
> This is a preview feature only. Data may not be fully synchronized. Doing backup is recommended before enabling it.

[Open Source Vulnerabilities](https://osv.dev) (OSV) is a vulnerability database and triage infrastructure for open source projects aimed at helping both open source maintainers and consumers of open source.
This infrastructure serves as an aggregator of vulnerability databases that have adopted the [OpenSSF Vulnerability format](https://github.com/ossf/osv-schema).

OSV additionally provides infrastructure to ensure affected versions are accurately represented in each vulnerability entry, through bisection and version analysis.

Dependency-Track integrates with OSV by mirroring advisories from GCS bucket maintained by OSV [gs://osv-vulnerabilities.](https://osv-vulnerabilities.storage.googleapis.com/).
The mirror is refreshed daily, or upon restart of the Dependency-Track instance.
No personal access token is required to authenticate with OSV.

![](../../images/osv-architecture.png)
<center><i style="font-size:80%">OSV Architecture</i></center>

**Ecosystems**

User can select specific ecosystems to mirror vulnerabilities from OSV. Ecosystems need to be selected (per requirement) in order to enable OSV feature.
Debian ecosystem package is superset of all individual versions, it is suggested to enable Debian alone instead of all Debian versions.

**NOTE**: Disabling the OSV would remove current ecosystem selection, but already mirrored vulnerabilities would be retained.

![](../../images/osv-configuration.png)

This integration will enable vulnerability DB of selective ecosystems in DT (as shown). It can be also used in an offline mode (without having internet access to the DT API server).

Current defined ecosystems are below. Updated list can be found at [https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt).

|  Ecosystem | Description                                                                                                                                                                                                                                                                                                          |
|-----|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  Go   | 	The Go ecosystem                                                                                                                                                                                                                                                                                                    |
|  npm   | The NPM ecosystem                                                                                                                                                                                                                                                                                                    |
|  OSS-Fuzz | For reports from the OSS-Fuzz project that have no more appropriate ecosystem                                                                                                                                                                                                                                        |
|  PyPI   | the Python PyPI ecosystem                                                                                                                                                                                                                                                                                            |
|  RubyGems | The RubyGems ecosystem                                                                                                                                                                                                                                                                                               |
|  crates.io | The crates.io ecosystem for Rust                                                                                                                                                                                                                                                                                     |
|  Packagist | The PHP package manager ecosystem                                                                                                                                                                                                                                                                                    |
|  Maven   | The Maven Java package ecosystem                                                                                                                                                                                                                                                                                     |
|  NuGet   | The NuGet package ecosystem                                                                                                                                                                                                                                                                                          |
|  Linux   | The Linux kernel                                                                                                                                                                                                                                                                                                     |
|  Debian  | The Debian package ecosystem; The ecosystem string might optionally have a :<RELEASE> suffix to scope the package to a particular Debian release. <RELEASE> is a numeric version specified in the [Debian distro-info-data](https://debian.pages.debian.net/distro-info-data/debian.csv). For example, the ecosystem string “Debian:7” refers to the Debian 7 (wheezy) release. |
|  Hex | The package manager for the Erlang ecosystem                                                                                                                                                                                                                                                                         |
|  Android   | The Android ecosystem                                                                                                                                                                                                                                                                                                |
|  GitHub Actions |    The GitHub Actions ecosystem                                                                                                                                                                                                                                                                                                                  |
|  Pub |        The package manager for the Dart ecosystem                                                                                                                                                                                                                                                                                                              |