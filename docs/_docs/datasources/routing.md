---
title: Datasource Routing
category: Datasources
chapter: 3
order: 4
---

Components often belong to one or more ecosystems. These ecosystems typically have one or more sources of 
truth that provide additional data about the components. For example, Maven Central and the NPM repository provide 
information about Java and Node components respectively. Likewise, NPM public advisories provides vulnerability 
intelligence specific to Node modules.

Dependency-Track has adopted an emerging spec called [Package URL](https://github.com/package-url/purl-spec) that
provides a flexible way to represent metadata about components and their place in various ecosystems.

> It's highly recommended that every component being tracked by the system have a valid Package URL. 

### Package URL (purl)

Package URL was created to standardize how software package metadata is represented so that packages could universally
be located regardless of what vendor, project, or ecosystem the packages belong. Package URL conforms to [RFC-3986](https://tools.ietf.org/html/rfc3986).

The syntax of Package URL is:
```
scheme:type/namespace/name@version?qualifiers#subpath
```

* **Scheme**: Will always be 'pkg' to indicate a Package URL (required)
* **Type**: The package "type" or package "protocol" such as maven, npm, nuget, gem, pypi, etc. Required.
* **Namespace**: Some name prefix such as a Maven groupid, a Docker image owner, a GitHub user or organization. Optional and type-specific.
* **Name**: The name of the package. Required.
* **Version**: The version of the package. Optional.
* **Qualifiers**: Extra qualifying data for a package such as an OS, architecture, a distro, etc. Optional and type-specific.
* **Subpath**: Extra subpath within a package, relative to the package root. Optional.

#### Examples:

```
pkg:maven/org.apache.commons/io@1.3.4

pkg:golang/google.golang.org/genproto#googleapis/api/annotations

pkg:gem/jruby-launcher@1.1.2?platform=java

pkg:npm/%40angular/animation@12.3.1

pkg:nuget/EnterpriseLibrary.Common@6.0.1304

pkg:pypi/django-package@1.11.1.dev1
```

### Package URL and Dependency-Track

Dependency-Track uses Package URL in several ways:

* Routes the identification of vulnerabilities to one or more internal scanners
* Reduces false positives and false negatives by using the scanner that is most appropriate to the ecosystem the component belongs
* Works in conjunction with numerous repositories to identify outdated components across multiple ecosystems

The default scanner, if a Package URL is not specified for a component, is to use Dependency-Check's ability to perform
fuzzy matching against the NVD. This approach may work for some components, but in the case of Node modules, would lead
to both false positives and negatives. If a valid Package URL was specified for a Node module for instance, Dependency-Track
would use it's own internal NPM audit scanner, thus providing more actionable and accurate results.

Dependency-Track (as of v3.1.0) also provides the ability to determine out-of-date components. It uses the Package URL
of the component and maps it to a corresponding list of repositories that have been configured to support the components 
ecosystem.

Refer to [Repositories]({{ site.baseurl }}{% link _docs/datasources/repositories.md %}) for further information.

### Package URL support in Bill-of-Materials

The CycloneDX BoM specification supports Package URL on a per-component basis. Users of the 
[CycloneDX Maven plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) or
[CycloneDX Node module](https://github.com/CycloneDX/cyclonedx-node-module) will automatically have valid Package URLs 
for every component in the resulting BoM. 

When importing dependency-check-report.xml, Dependency-Track will attempt to automatically generate Package URLs for 
every component identified. Support is currently limited to Maven and npm.

When importing SPDX BoM documents, Package URL identification cannot be automatically determined, although support 
for Package URL may be coming to the SPDX specification in a future release.