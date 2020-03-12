---
title: OpenID Connect Configuration
category: Getting Started
chapter: 1
order: 9
---

Dependency-Track has been tested with multiple OpenID Connect Identity Providers. The following are
some example configurations that are known to work.

#### General

```ini
# Enable OpenID Connect
alpine.oidc.enabled=true

# Enable user provisioning for OpenID Connect
# Keep this disabled when using public Identity Providers!
alpine.oidc.user.provisioning=true

# Synchronize teams with the roles of OpenID Connect users
alpine.oidc.team.synchronization=true
```

#### GitLab (gitlab.com)

```ini
alpine.oidc.discovery.uri=https://gitlab.com/.well-known/openid-configuration
alpine.oidc.username.claim=nickname
alpine.oidc.teams.claim=groups
```

Please refer to the official documentation on [how to use GitLab as OpenID Connect Identity Provider](https://docs.gitlab.com/ee/integration/openid_connect_provider.html).

#### Google

```ini
alpine.oidc.discovery.uri=https://accounts.google.com/.well-known/openid-configuration
alpine.oidc.username.claim=name

# Google does not support groups 
alpine.oidc.team.synchronization=false
```

Please refer to the [OpenID Connect documentation of Google Identity Platform](https://developers.google.com/identity/protocols/oauth2/openid-connect#discovery).

#### Keycloak

```ini
alpine.oidc.discovery.uri=http://localhost:8080/auth/realms/master/.well-known/openid-configuration
alpine.oidc.username.claim=preferred_username
alpine.oidc.teams.claim=group
```

<!-- TODO: Show how to include roles / group in UserInfo as this is disabled per default --> 