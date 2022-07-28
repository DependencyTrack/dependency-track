---
title: Datasource Routing
category: Datasources
chapter: 4
order: 6
---

Components often belong to one or more ecosystems. These ecosystems typically have one or more sources of 
truth that provide additional data about the components. For example, Maven Central and the NPM repository provide 
information about Java and Node components respectively. 

Dependency-Track has adopted an emerging spec called [Package URL](https://github.com/package-url/purl-spec) that
provides a flexible way to represent metadata about components and their place in various ecosystems.

> It's highly recommended that every software component being tracked by the system have a valid Package URL. 

### Package URL (PURL)

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

* Routes the identification of vulnerabilities to one or more analyzers
* Reduces false positives and false negatives by using the analyzer that is most appropriate to the ecosystem the component belongs
* Works in conjunction with numerous repositories to identify outdated components across multiple ecosystems

Dependency-Track provides the ability to determine out-of-date components. It uses the Package URL
of the component and maps it to a corresponding list of repositories that have been configured to support the components 
ecosystem.

Refer to [Repositories]({{ site.baseurl }}{% link _docs/datasources/repositories.md %}) for further information.

### Package URL support in Bill-of-Materials

All version of the CycloneDX BOM specification support Package URL. Users of official CycloneDX 
implementations for various build systems will automatically have valid Package URLs for every component in the 
resulting BOM.

### Common Platform Enumeration (CPE)
Like Package URL, the Common Platform Enumeration (CPE) specification is a structured naming scheme for applications, 
operating systems, and hardware.

The syntax of CPE is:
```
cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
```

* **Part**: Specifies an application (a), operating system (o), or hardware (h) component. Required
* **Vendor**: The name of the vendor as defined in the CPE dictionary Required.
* **Product**: The name of the affected product. Required.
* **Version**: The affected version. 
* **Update**: The update of the package.
* **Edition**: Legacy edition (deprecated)
* **Language**: Any language defined in RFC-5646
* **SW Edition**: The software edition
* **Target SW**: The software environment in which the product operates
* **Target HW**: The hardware environment in which the product operates
* **Other**: Vendor or product-specific information

#### Examples:

```
cpe:2.3:a:joomla:joomla\!:3.9.8:*:*:*:*:*:*:*

cpe:2.3:o:redhat:enterprise_linux_server_eus:7.7:*:*:*:*:*:*:*

cpe:2.3:h:intel:core_i7:870:*:*:*:*:*:*:*
```


### CPE and Dependency-Track

Dependency-Track uses CPE with its internal analyzer. 
The internal analyzer relies on a dictionary of vulnerable software. This dictionary is automatically populated when 
NVD mirroring or VulnDB mirroring is performed. The internal analyzer is used by all components with valid CPEs, 
including application, operating system, and hardware components.

Components with a valid CPE defined, will use the internal analyzer (and optionally the VulnDB analyzer) to identify
known vulnerabilities.
