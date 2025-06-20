---
title: SVG Badges
category: Integrations
chapter: 6
order: 10
---

Dependency-Track supports badges in Scalable Vector Graphics (SVG) format. Support for badges is configurable on a team
basis via permission or globally for unauthenticated access.

To enable badges for a team, activate the permission `VIEW_BADGES`. To deactivate badges, remove the permission. To 
retrieve a badge, use a team's API key either in the badge API header `X-Api-Key` or in the URI parameter `apiKey`.

As an alternative, badges can also be accessed without authentication. On new Dependency-Track installations, this is
disabled by default. On Dependency-Track installations updated from &leq; v4.11, where (unauthenticated) badge support 
was enabled, badges will remain accessible for unauthenticated requests. If this is disabled, badges will be accessible
for authenticated and authorized requests.

> Enabling unauthenticated access to badges will provide vulnerability and policy violation metric information to
> unauthenticated users. Any anonymous user with network access to Dependency-Track and knowledge of a projects
> information will be able to view the SVG badge.
> 
> It is however offered as an alternative in case publishing badge URLs containing an API key raises security concerns
> or compliance issues with your Dependency-Track installation.
> Be aware of the following risks that go with publishing API keys, even if scoped entirely to badges:
> * a developer could accidentally commit and push the wrong API key in the Dependency-Track badge URL, e.g. in their 
>   project's README.md, and thus publish a secret API key, creating a security incident 
> * contradicts common compliance rules to never publish secrets like API keys, raising the complexity of a 
>   technological environment.

Dependency-Track ships with a default team "_Badge Viewers_" dedicated to badges that already has the necessary
permission and an API key.

> As badges are typically embedded in places that more people have access to than to Dependency-Track, the API key used
> for the badge request should have minimal scope to prevent unintended access beyond that badge. Ideally, the API
> key belongs to a single-purpose team, having just the `VIEW_BADGES` permission, with only one API key and access to 
> only the projects/project versions whose badges are displayed at one site--the latter requiring _Portfolio Access 
> Control_.

In all following examples, replace `{name}`, `{version}`, `{uuid}`, and `{apiKey}` with their respective values. For
brevity, the examples use the URI query parameter as the method of authentication, however, they also work with
authentication by header.

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
https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version}?apiKey={apiKey}
https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}?apiKey={apiKey}
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
https://dtrack.example.com/api/v1/badge/violations/project/{name}/{version}?apiKey={apiKey}
https://dtrack.example.com/api/v1/badge/violations/project/{uuid}?apiKey={apiKey}
```


### Embedding
You can embed the badges in other documents. It allows you to display a badge in your README for example.

#### HTML Examples
```html
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version}?apiKey={apiKey}">
<img src="https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}?apiKey={apiKey}">
<img src="https://dtrack.example.com/api/v1/badge/violations/project/{name}/{version}?apiKey={apiKey}">
<img src="https://dtrack.example.com/api/v1/badge/violations/project/{uuid}?apiKey={apiKey}">
```

#### Markdown Examples
```markdown
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{name}/{version}?apiKey={apiKey})
![alt text](https://dtrack.example.com/api/v1/badge/vulns/project/{uuid}?apiKey={apiKey})
![alt text](https://dtrack.example.com/api/v1/badge/violations/project/{name}/{version}?apiKey={apiKey})
![alt text](https://dtrack.example.com/api/v1/badge/violations/project/{uuid}?apiKey={apiKey})
```

