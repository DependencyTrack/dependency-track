---
title: Users and Permissions
category: Administration
chapter: 12
order:
---

### Permissions

The OpenAPI specification describes the required permissions for each REST
call. This page gives a short, non-exhaustive overview.

| Permission                  | Grants permission to …                                                                        |
|-----------------------------|-----------------------------------------------------------------------------------------------|
| `ACCESS_MANAGEMENT`         | Manage users, permissions, teams, ACLs, LDAP                                                  |
| `BOM_UPLOAD`                | Upload BOMs                                                                                   |
| `POLICY_MANAGEMENT`         | Manage policies, services, license groups                                                     |
| `POLICY_VIOLATION_ANALYSIS` | VEX analysis, modify violation analysis                                                       |
| `PORTFOLIO_MANAGEMENT`      | Modify projects, metrics, policies                                                            |
| `PROJECT_CREATION_UPLOAD`   | Auto-create a project when uploading a BOM                                                    |
| `SYSTEM_CONFIGURATION`      | Read and modify configuration properties, repositories, integrations, licenses, notifications |
| `TAG_MANAGEMENT`            | Modify tags                                                                                  |
| `VIEW_BADGES`               | Read badges                                                                                   |
| `VIEW_POLICY_VIOLATION`     | Read policy violations                                                                        |
| `VIEW_PORTFOLIO`            | Read projects, services, tags, vulnerabilities, BOMs, Dependency Graph, metrics; use Search   |
| `VIEW_VULNERABILITY`        | Read analysis decisions and findings                                                          |
| `VULNERABILITY_ANALYSIS`    | Record analysis decision                                                                      |
| `VULNERABILITY_MANAGEMENT`  | Modify vunlerabilities                                                                        |
