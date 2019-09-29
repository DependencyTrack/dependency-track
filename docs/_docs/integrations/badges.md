---
title: SVG Badges
category: Integrations
chapter: 6
order: 9
---

Dependency-Track supports badges in Scalable Vector Graphics (SVG) format. Support for badges is a globally configurable
option and is disabled by default.

<img src="/images/badge-project-vulns.svg" width="234"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-novulns.svg" width="144"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-nometrics.svg" width="148"/>

> Enabling badge support will provide vulnerability metric information to unauthenticated users. Any anonymous
> user with network access to Dependency-Track and knowledge of a projects UUID will be able to view the SVG badge.

### HTML Example
```html
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}">
```

### Markdown Example
```markdown
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{uuid})
```

In both examples, replace `{uuid}` with actual value of the project's UUID. The project UUID is displayed as 
part of the URL when viewing the project in Dependency-Track.
