---
title: Auditing Basics
category: Triage Results
chapter: 5
order: 1
---

Dependency-Track incorporates an enterprise-class auditing workflow engine capable of keeping track of audit history, 
comments and analysis decisions for all findings. Auditing can be performed on a per-project basis, or globally on 
components themselves.

### Project Auditing

If a project relies on specific components, the project has a 'dependency' on those components. Project auditing is 
the process of triaging findings on the dependencies for each project.

![Project Auditing](/images/screenshots/audit-finding-project.png)

> Audit decisions, comments, and audit history performed on a project only affect the findings for said project.

The **VULNERABILITY_ANALYSIS** permission is required to perform project auditing.


### Component Auditing

Dependency-Track includes the ability to globally modify metadata for components. This affects all projects that have
a dependency on the components being modified. Like all global component metadata, audit decisions made at the component
level have a global effect on all projects that use those components.

![Component Auditing](/images/screenshots/audit-finding-component.png)

> Audit decisions, comments, and audit history performed on a component affect all projects that have a dependency on 
> said component. Suppressing findings on individual components will suppress the finding for all projects that have
> a dependency on the component.

The **VULNERABILITY_ANALYSIS** and **PORTFOLIO_MANAGEMENT** permissions are required to perform global component auditing.
