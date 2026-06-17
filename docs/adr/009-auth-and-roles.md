| Status   | Date       | Author(s)                                  |
| :------- | :--------- | :----------------------------------------- |
| Proposed | 2025-05-14 | [@jmayer-lm](https://github.com/jmayer-lm) |

## Context

The Dependency Track system currently faces challenges with its permission structure, lacking clear role definitions and appropriate access controls. To address these issues, a comprehensive overhaul of the permission system is proposed. This initiative aims to refine and fix the existing permissions, introduce roles, and enhance the overall access management within Dependency Track.

## Decision

We decide to implement a comprehensive overhaul of the Dependency Track permission system, incorporating the following key elements:

- Introducing "roles" means assigning groups of permissions to specific types of users (e.g., Admin, Auditor, etc). This allows for more granular control over what actions different types of users can perform within the system.
- Implement Query Manager changes to enforce permissions at the project level. This will ensure that users can only view and modify projects they have access to.
- Split the current permission set into global and team/project-based permission sets, adding any potentially missing ones to ensure comprehensive coverage of access scenarios. Global permissions are applied universally across the system and are not specific to any project or team. Team/Project-based permissions are specific to individual teams or projects, allowing for more customized access control within those contexts.
- Add custom roles, the abilitiy to create tailored sets of permssions specifc to the type of user, to Dependency Track with a field to link to external services, enhancing integration capabilities and allowing for more seamless interactions with other tools and platforms.
- Separate Team administration from system administration, clarifying roles and responsibilities to prevent confusion and minimize the risk of unintended system-wide changes.

## Data Model

```mermaid

erDiagram
    %% Table Definitions
    ROLE {
        bigint ID PK
        text NAME
        uuid UUID
    }

    USER {
        bigint ID PK
    }

    PERMISSION {
        bigint ID PK
        text DESCRIPTION
        text NAME
    }

    ROLES_PERMISSIONS {
        bigint ROLE_ID FK "References ROLE(ID)"
        bigint PERMISSION_ID FK "References PERMISSION(ID)"
    }

    USERS_ROLES {
        bigint USER_ID FK "References USER(ID)"
        bigint ROLE_ID FK "References ROLE(ID)"
    }

    %% Relationships for USERS_ROLES: This table associates a USER and a ROLE.
    USER ||--o{ USERS_ROLES : "assigned"
    ROLE ||--o{ USERS_ROLES : "applied to"

    %% Relationships between ROLE and PERMISSION via ROLES_PERMISSIONS
    ROLE ||--o{ ROLES_PERMISSIONS : "has"
    PERMISSION ||--o{ ROLES_PERMISSIONS : "assigned via"
```

## Consequences

The implementation of the new permission system and roles in Dependency Track is expected to have the following consequences:

- Improved Security: The introduction of more granular permission controls and the separation of team administration from system administration will reduce the risk of unauthorized access to sensitive features and data, enhancing the overall security posture of the platform.
- Enhanced Usability: By providing more tailored and flexible access controls, users will have a more streamlined experience, with access to the features and resources they need to perform their tasks, without being overwhelmed by unnecessary permissions or complexity.
- Reduced Administrative Burden: The clarification of roles and responsibilities, particularly the distinction between team and system administration, will simplify the management of the platform, reducing the administrative workload and making it easier to maintain and evolve the system over time.
- Better Scalability: The introduction of custom roles and the ability to link to external services will make it easier for Dependency Track to integrate with other tools and platforms, improving its scalability and adaptability to different use cases and environments.
- Increased Complexity for Small Teams: For very small teams or individual users, the introduction of more granular permission controls might add complexity, potentially making it more challenging to manage permissions and access. Guidance and documentation will be crucial in mitigating this impact.

