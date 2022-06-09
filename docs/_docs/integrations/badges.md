---
title: SVG Badges
category: Integrations
chapter: 6
order: 10
---

Dependency-Track supports badges in Scalable Vector Graphics (SVG) format. Support for badges is a globally configurable
option and is disabled by default.

> Enabling badge support will provide vulnerability and policy violation metric information to unauthenticated users.
> Any anonymous user with network access to Dependency-Track and knowledge of a projects information will be able
> to view the SVG badge.

In all following examples, replace `{name}`, `{version}`, and `{uuid}` with their respective values.

### Vulnerable components
Create a badge for vulnerable components of the project. It either shows:

* the severity of the vulnerabilities.
* "no vulns" if there are no vulnerabilities.
* "no metrics" if metrics for the project aren't collect yet.

<img src="/images/badge-project-vulns.svg" width="234"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-vulns-none.svg" width="144"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-vulns-nometrics.svg" width="148"/>

Suppressed vulnerabilities are not included in the count, so a project with only suppressed vulnerabilities will show
a "no vulns" badge. SVG badges may be retrieved using either the UUID of the project, or the combination of a projects
name and version.

#### Examples
```
https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version}
https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}
```

### Policy violations
Create a badge for policy violations of the project. It either shows:

* the state of the violation.
* "no violations" if there are no violations.
* "no metrics" if metrics for the project aren't collect yet.

<img src="/images/badge-project-violations.svg" width="140"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-violations-none.svg" width="124"/>
&nbsp;&nbsp;&nbsp;
<img src="/images/badge-project-violations-nometrics.svg" width="114"/>

Suppressed violations are not included in the count, so a project with only suppressed violations will show
a "no violations" badge. SVG badges may be retrieved using either the UUID of the project, or the combination of a
projects name and version.

#### Examples

```
https://dtrack.example.com/api/v1/badge/violations/project/{name}/{version}
https://dtrack.example.com/api/v1/badge/violations/project/{uuid}
```


### Embedding
You can embed the badges in other documents. It allows you to display a badge in your README for example.

#### HTML Examples
```html
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version}">
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}">
<img src="https://dtrack.example.com/api/v1/badge/violations/project/{name}/{version}">
<img src="https://dtrack.example.com/api/v1/badge/violations/project/{uuid}">
```

#### Markdown Examples
```markdown
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version})
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{uuid})
![alt text](https://dtrack.example.com/api/v1/badge/violations/project/{name}/{version})
![alt text](https://dtrack.example.com/api/v1/badge/violations/project/{uuid})
```

