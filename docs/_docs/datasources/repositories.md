---
title: Repositories
category: Datasources
chapter: 3
order: 5
---

Dependency-Track relies on integration with external repositories to help identify metadata that may be useful
for the identification of risk. Repositories are typically used in software engineering as a way to manage and 
automatically resolve dependencies.

Dependency-Track incorporates the concept of repositories, completely independent of software engineering use-cases, 
as a way to gain additional intelligence about the components it's tracking. Dependency-Track brings the power of
external repositories to every project the system tracks, whether the project is internally developed or commercial
off-the-shelf software.

Dependency-Track supports the following repositories:

| Ecosystem | Repository       | Resolution Order |
| --------- | ---------------- | ---------------- |
| gem       | RubyGems         | 1 |
| maven     | Maven Central    | 1 |
|           | Atlassian Public | 2 |
|           | JBoss Releases   | 3 |
|           | Clojars          | 4 |
|           | Google Android   | 5 |
| npm       | NPM              | 1 |


> Future versions of Dependency-Track will support configurable repositories and additional ecosystems.


### Outdated Version Tracking

One primary use-case for the support of repositories is the identification of outdated components. By leveraging tight 
integration with APIs available from various repositories, the platform can identify outdated versions of components 
across multiple ecosystems. Dependency-Track relies on Package URL (purl) to identify the ecosystem a component belongs 
to, the metadata about the component, and uses that data to query the various repositories capable of supporting the 
components ecosystem.

Package URL is natively supported in the [CycloneDX](http://cyclonedx.org/) BoM specification. By using CycloneDX as a 
means to populate project dependencies, organizations benefit from the many use-cases Package URL provides, including
leveraging repositories to identify outdated components.

Refer to [Supply Chain Risk Management]({{ site.baseurl }}{% link _docs/usage/scrm.md %}) for additional information on
the benefits of tracking outdated components and to [Datasource Routing]({{ site.baseurl }}{% link _docs/datasources/routing.md %})
for information on Package URL and the various ways its used throughout Dependency-Track.