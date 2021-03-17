---
title: REST API
category: Integrations
chapter: 6
order: 8
---

Dependency-Track is built using a *thin server architecture* and an *API-first design*. API's are simply at the heart
of the platform. Every API is fully documented via Swagger 2.0.

> http://{hostname}:{port}/api/swagger.json

The Swagger UI Console (not included) can be used to visualize and explore the wide range of possibilities. Chrome and
FireFox extensions can be use to quickly use the Swagger UI Console.

![Swagger UI Console](/images/screenshots/swagger-ui-console.png)

Prior to using the REST APIs, an API Key must be generated. By default, creating a team will also create a corresponding
API key. A team may have multiple keys.

![Teams - API Key](/images/screenshots/teams.png)
