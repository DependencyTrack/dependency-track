---
title: OpenID Connect Configuration
category: Getting Started
chapter: 1
order: 9
---

Generally, Dependency-Track can be used with any identity provider that implements the [OpenID Connect standard](https://openid.net/connect/).
connect2id maintains a list of [public OpenID Connect Identity Providers](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/openid-connect-providers).
Although usage with public providers is technically possible, it's strongly recommended to only use providers
that you or your organization have full control over. Misconfiguration may allow third parties to gain access to
your Dependency-Track instance!

Dependency-Track has been tested with multiple OpenID Connect identity providers. The following are
some example configurations that are known to work. If you find that the provider of your choice does not work
with Dependency-Track, please [file an issue](https://github.com/DependencyTrack/dependency-track/issues).

#### GitLab (gitlab.com)

```ini
alpine.oidc.enabled=true
alpine.oidc.discovery.uri=https://gitlab.com/.well-known/openid-configuration
alpine.oidc.user.provisioning=true
alpine.oidc.username.claim=nickname
alpine.oidc.team.synchronization=true
alpine.oidc.always.sync.teams=true
alpine.oidc.teams.claim=groups
```

Please refer to the official documentation on [how to use GitLab as OpenID Connect Identity Provider](https://docs.gitlab.com/ee/integration/openid_connect_provider.html).

#### Keycloak

```ini
alpine.oidc.enabled=true
alpine.oidc.discovery.uri=http://localhost:8080/auth/realms/master/.well-known/openid-configuration
alpine.oidc.user.provisioning=true
alpine.oidc.username.claim=preferred_username
alpine.oidc.team.synchronization=true
alpine.oidc.always.sync.teams=true
alpine.oidc.teams.claim=group
```

Keycloak does not include group or role information in its UserInfo endpoint per default. If you want to use 
Dependency-Track's team synchronization feature, you'll have to create a mapper for the Dependency-Track client:

![Mapper creation](/images/screenshots/oidc-keycloak-groups-mapping.png)

Depending on your setup you would use the mapper types `Group Membership` (as shown above) or `User Realm Role`.
Make sure `Add to userinfo` is enabled.
