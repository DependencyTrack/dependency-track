---
title: SVG Badges
category: Integrations
chapter: 6
order: 10
---

Dependency-Track supports badges in Scalable Vector Graphics (SVG) format. Support for badges is a globally configurable
option and is disabled by default.

<img src="/images/badge-project-vulns.svg" width="234"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-novulns.svg" width="144"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-nometrics.svg" width="148"/>

> Enabling badge support will provide vulnerability metric information to unauthenticated users. Any anonymous
> user with network access to Dependency-Track and knowledge of a projects information will be able to view the SVG badge.

SVG badges may be retrieved using either the UUID of the project, or the combination of a
projects name and version.

### HTML Examples
```html
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version}">
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}">
```

### Markdown Examples
```markdown
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version})
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{uuid})
```

In all examples, replace `{name}`, `{version}`, and `{uuid}` with their respective values.
