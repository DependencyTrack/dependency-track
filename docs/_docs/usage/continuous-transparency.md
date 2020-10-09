---
title: Continuous Transparency
category: Usage
chapter: 2
order: 2
---

Much of the focus of Dependency-Track centers around the consumption and analysis of SBOMs. However, Dependency-Track
is also capable of generating SBOMs from any project in the portfolio. Organizations are able to create SBOMs when
requested by customers, partners, or other stakeholders for any project in the portfolio.

Organizations that require greater levels of transparency may optionally use Dependency-Tracks notification feature
which is capable of publishing SBOMs via webhooks whenever an SBOM is consumed or processed by the system. When used
in a continuous integration or delivery environment, SBOMs can optionally be published to one or more endpoints
thus achieving continuous transparency with pre-determined parties.

Although continuous transparency is possible, the radius of transparency should be carefully considered. Organizations
are encouraged to start with sharing SBOM data with other departments or business units within the same organization
prior to sharing data with external parties.

Refer to [Notifications]({{ site.baseurl }}{% link _docs/integrations/notifications.md %}) for information on sharing
SBOM data via webhooks on `BOM_CONSUMED` and `BOM_PROCESSED` events.
