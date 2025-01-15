---
title: Collection Projects
category: Usage
chapter: 2
order: 8
---

Dependency-Track does support organizing projects in a tree structure 
via parent-child relationships. This can be used to organize projects 
for example by department or team, but also to structure a project itself 
into different sub-projects and to organize their versions. 

Since v4.13 it also supports configuring parents as "Collection Projects", 
which allows to define that a parent itself does not host any components,
but instead aggregates metrics of vulnerabilities and policy violations of
its children with one of three possible calculation methods:
* Aggregate all direct children
* Aggregate all direct children which have a tag of your choice
* Aggregate all direct children which are marked as latest version

This allows a wide range use cases to be displayed. See following screenshot 
which demonstrates a combination of all 3 possibilities within one product, 
which consists of a Web Frontend (tracking DEV, QA, PROD environment), a Backend 
with multiple MicroServices (tracked separated by DEV, QA, PROD environment), 
and a mobile app (tracking each released version of the app).

![collection project structure](/images/screenshots/collection-projects-structure.png)

This is just one example how you could structure your projects and make use of 
collection projects to better visualize the projects state without going down into 
each single level. There are many other possibilities how you can organize the portfolio.

Collection projects do not show the usual tabs for components, vulnerabilities etc.
Instead they show a list of projects contained in this collection and their metrics:

![collection projects details](/images/screenshots/collection-projects-details.png)

Collection projects can be easily identified via the "calculator" icon, and hovering it
displays the applied collection logic.