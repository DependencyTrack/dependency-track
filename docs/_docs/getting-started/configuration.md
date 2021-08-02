---
title: Configuration
category: Getting Started
chapter: 1
order: 5
---

### Backend

The central configuration file `application.properties` resides in the classpath of the WAR by default. 
This configuration file controls many performance tuning parameters but is most useful for defining
optional external database sources, directory services (LDAP), and proxy settings.

For containerized deployments, the properties defined in the configuration file can also be specified 
as environment variables. All environment variables are upper case with periods (.) replaced with underscores (_).
Refer to the [Docker instructions]({{ site.baseurl }}{% link _docs/getting-started/deploy-docker.md %}) for 
configuration examples using environment variables.

Dependency-Track administrators are highly encouraged to create a copy of this file in the
Dependency-Track data directory and customize it prior to deploying to production.


> The default embedded H2 database is designed to quickly evaluate and experiment with Dependency-Track.
> Do not use the embedded H2 database in production environments. 
> 
> See: [Database Support]({{ site.baseurl }}{% link _docs/getting-started/database-support.md %}).


To start Dependency-Track using custom configuration, add the system property 
`alpine.application.properties` when executing. For example:

```bash
-Dalpine.application.properties=~/.dependency-track/application.properties
```

#### Default configuration

```ini
############################ Alpine Configuration ###########################

# Required
# Defines the number of worker threads that the event subsystem will consume.
# Events occur asynchronously and are processed by the Event subsystem. This
# value should be large enough to handle most production situations without
# introducing much delay, yet small enough not to pose additional load on an
# already resource-constrained server.
# A value of 0 will instruct Alpine to allocate 1 thread per CPU core. This
# can further be tweaked using the alpine.worker.thread.multiplier property.
# Default value is 0.
alpine.worker.threads=0

# Required
# Defines a multiplier that is used to calculate the number of threads used
# by the event subsystem. This property is only used when alpine.worker.threads
# is set to 0. A machine with 4 cores and a multiplier of 4, will use (at most)
# 16 worker threads. Default value is 4.
alpine.worker.thread.multiplier=4

# Required
# Defines the path to the data directory. This directory will hold logs, keys,
# and any database or index files along with application-specific files or 
# directories.
alpine.data.directory=~/.dependency-track

# Required
# Defines the interval (in seconds) to log general heath information. If value
# equals 0, watchdog logging will be disabled.
alpine.watchdog.logging.interval=0

# Required
# Defines the database mode of operation. Valid choices are:
# 'server', 'embedded', and 'external'.
# In server mode, the database will listen for connections from remote hosts.
# In embedded mode, the system will be more secure and slightly faster. 
# External mode should be used when utilizing an external database server 
# (i.e. mysql, postgresql, etc).
alpine.database.mode=embedded

# Optional
# Defines the TCP port to use when the database.mode is set to 'server'.
alpine.database.port=9092

# Required
# Specifies the JDBC URL to use when connecting to the database.
alpine.database.url=jdbc:h2:~/.dependency-track/db

# Required
# Specifies the JDBC driver class to use.
alpine.database.driver=org.h2.Driver

# Optional
# Specifies the username to use when authenticating to the database.
alpine.database.username=sa

# Optional
# Specifies the password to use when authenticating to the database.
# alpine.database.password=

# Optional
# Specifies if the database connection pool is enabled.
alpine.database.pool.enabled=true

# Optional
# This property controls the maximum size that the pool is allowed to reach,
# including both idle and in-use connections.
alpine.database.pool.max.size=20

# Optional
# This property controls the minimum number of idle connections in the pool.
# This value should be equal to or less than alpine.database.pool.max.size.
# Warning: If the value is less than alpine.database.pool.max.size, 
# alpine.database.pool.idle.timeout will have no effect.
alpine.database.pool.min.idle=10

# Optional
# This property controls the maximum amount of time that a connection is
# allowed to sit idle in the pool.
alpine.database.pool.idle.timeout=300000

# Optional
# This property controls the maximum lifetime of a connection in the pool.
# An in-use connection will never be retired, only when it is closed will
# it then be removed.
alpine.database.pool.max.lifetime=600000

# Optional
# When authentication is enforced, API keys are required for automation, and
# the user interface will prevent anonymous access by prompting for login
# credentials.
alpine.enforce.authentication=true

# Optional
# When authorization is enforced, team membership for both API keys and user
# accounts are restricted to what the team itself has access to. To enforce 
# authorization, the enforce.authentication property (above) must be true.
alpine.enforce.authorization=true

# Required
# Specifies the number of bcrypt rounds to use when hashing a users password.
# The higher the number the more secure the password, at the expense of
# hardware resources and additional time to generate the hash.
alpine.bcrypt.rounds=14

# Required
# Defines if LDAP will be used for user authentication. If enabled,
# alpine.ldap.* properties should be set accordingly.
alpine.ldap.enabled=false

# Optional
# Specifies the LDAP server URL
# Example (Microsoft Active Directory):
#    alpine.ldap.server.url=ldap://ldap.example.com:3268
#    alpine.ldap.server.url=ldaps://ldap.example.com:3269
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.server.url=ldap://ldap.example.com:389
#    alpine.ldap.server.url=ldaps://ldap.example.com:636
alpine.ldap.server.url=ldap://ldap.example.com:389

# Optional
# Specifies the base DN that all queries should search from
alpine.ldap.basedn=dc=example,dc=com

# Optional
# Specifies the LDAP security authentication level to use. Its value is one of
# the following strings: "none", "simple", "strong". If this property is empty
# or unspecified, the behaviour is determined by the service provider.
alpine.ldap.security.auth=simple

# Optional
# If anonymous access is not permitted, specify a username with limited access
# to the directory, just enough to perform searches. This should be the fully
# qualified DN of the user.
alpine.ldap.bind.username=

# Optional
# If anonymous access is not permitted, specify a password for the username
# used to bind.
alpine.ldap.bind.password=

# Optional
# Specifies if the username entered during login needs to be formatted prior
# to asserting credentials against the directory. For Active Directory, the
# userPrincipal attribute typically ends with the domain, whereas the
# samAccountName attribute and other directory server implementations do not.
# The %s variable will be substitued with the username asserted during login.
# Example (Microsoft Active Directory):
#    alpine.ldap.auth.username.format=%s@example.com
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.auth.username.format=%s
alpine.ldap.auth.username.format=%s@example.com

# Optional
# Specifies the Attribute that identifies a users ID
# Example (Microsoft Active Directory):
#    alpine.ldap.attribute.name=userPrincipalName
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.attribute.name=uid
alpine.ldap.attribute.name=userPrincipalName

# Optional
# Specifies the LDAP attribute used to store a users email address
alpine.ldap.attribute.mail=mail

# Optional
# Specifies the LDAP search filter used to retrieve all groups from the
# directory.
# Example (Microsoft Active Directory):
#    alpine.ldap.groups.filter=(&(objectClass=group)(objectCategory=Group))
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.groups.filter=(&(objectClass=groupOfUniqueNames))
alpine.ldap.groups.filter=(&(objectClass=group)(objectCategory=Group))

# Optional
# Specifies the LDAP search filter to use to query a user and retrieve a list
# of groups the user is a member of. The {USER_DN} variable will be substituted
# with the actual value of the users DN at runtime.
# Example (Microsoft Active Directory):
#    alpine.ldap.user.groups.filter=(&(objectClass=group)(objectCategory=Group)(member={USER_DN}))
# Example (Microsoft Active Directory - with nested group support):
#    alpine.ldap.user.groups.filter=(member:1.2.840.113556.1.4.1941:={USER_DN})
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.user.groups.filter=(&(objectClass=groupOfUniqueNames)(uniqueMember={USER_DN}))
alpine.ldap.user.groups.filter=(member:1.2.840.113556.1.4.1941:={USER_DN})

# Optional
# Specifies the LDAP search filter used to search for groups by their name.
# The {SEARCH_TERM} variable will be substituted at runtime.
# Example (Microsoft Active Directory):
#    alpine.ldap.groups.search.filter=(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.groups.search.filter=(&(objectClass=groupOfUniqueNames)(cn=*{SEARCH_TERM}*))
alpine.ldap.groups.search.filter=(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))

# Optional
# Specifies the LDAP search filter used to search for users by their name.
# The {SEARCH_TERM} variable will be substituted at runtime.
# Example (Microsoft Active Directory):
#    alpine.ldap.users.search.filter=(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))
# Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
#    alpine.ldap.users.search.filter=(&(objectClass=inetOrgPerson)(cn=*{SEARCH_TERM}*))
alpine.ldap.users.search.filter=(&(objectClass=user)(objectCategory=Person)(cn=*{SEARCH_TERM}*))

# Optional
# Specifies if mapped LDAP accounts are automatically created upon successful
# authentication. When a user logs in with valid credentials but an account has
# not been previously provisioned, an authentication failure will be returned.
# This allows admins to control specifically which ldap users can access the
# system and which users cannot. When this value is set to true, a local ldap
# user will be created and mapped to the ldap account automatically. This
# automatic provisioning only affects authentication, not authorization.
alpine.ldap.user.provisioning=false

# Optional
# This option will ensure that team memberships for LDAP users are dynamic and
# synchronized with membership of LDAP groups. When a team is mapped to an LDAP
# group, all local LDAP users will automatically be assigned to the team if
# they are a member of the group the team is mapped to. If the user is later
# removed from the LDAP group, they will also be removed from the team. This
# option provides the ability to dynamically control user permissions via an
# external directory.
alpine.ldap.team.synchronization=false

# Optional
# HTTP proxy. If the address is set, then the port must be set too.
# alpine.http.proxy.address=proxy.example.com
# alpine.http.proxy.port=8888
# alpine.http.proxy.username=
# alpine.http.proxy.password=
# alpine.no.proxy=localhost,127.0.0.1

# Optional
# Cross-Origin Resource Sharing (CORS) headers to include in REST responses.
# If 'alpine.cors.enabled' is true, CORS headers will be sent, if false, no
# CORS headers will be sent.
# See Also: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
# The following are default values
#alpine.cors.enabled=true
#alpine.cors.allow.origin=*
#alpine.cors.allow.methods=GET, POST, PUT, DELETE, OPTIONS
#alpine.cors.allow.headers=Origin, Content-Type, Authorization, X-Requested-With, Content-Length, Accept, Origin, X-Api-Key, X-Total-Count, *
#alpine.cors.expose.headers=Origin, Content-Type, Authorization, X-Requested-With, Content-Length, Accept, Origin, X-Api-Key, X-Total-Count
#alpine.cors.allow.credentials=true
#alpine.cors.max.age=3600

# Required
# Defines if OpenID Connect will be used for user authentication.
# If enabled, alpine.oidc.* properties should be set accordingly.
alpine.oidc.enabled=false

# Optional
# Defines the issuer URL to be used for OpenID Connect.
# This issuer MUST support provider configuration via the /.well-known/openid-configuration endpoint.
# See also:
# - https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
# - https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
alpine.oidc.issuer=

# Optional
# Defines the name of the claim that contains the username in the provider's userinfo endpoint.
# Common claims are "name", "username", "preferred_username" or "nickname".
# See also: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
alpine.oidc.username.claim=name

# Optional
# Specifies if mapped OpenID Connect accounts are automatically created upon successful
# authentication. When a user logs in with a valid access token but an account has
# not been previously provisioned, an authentication failure will be returned.
# This allows admins to control specifically which OpenID Connect users can access the
# system and which users cannot. When this value is set to true, a local OpenID Connect
# user will be created and mapped to the OpenID Connect account automatically. This
# automatic provisioning only affects authentication, not authorization.
alpine.oidc.user.provisioning=false

# Optional
# This option will ensure that team memberships for OpenID Connect users are dynamic and
# synchronized with membership of OpenID Connect groups or assigned roles. When a team is
# mapped to an OpenID Connect group, all local OpenID Connect users will automatically be
# assigned to the team if they are a member of the group the team is mapped to. If the user
# is later removed from the OpenID Connect group, they will also be removed from the team. This
# option provides the ability to dynamically control user permissions via the identity provider.
# Note that team synchronization is only performed during user provisioning and after successful
# authentication.
alpine.oidc.team.synchronization=false

# Optional
# Defines the name of the claim that contains group memberships or role assignments in the provider's userinfo endpoint.
# The claim must be an array of strings. Most public identity providers do not support group or role management.
# When using a customizable / on-demand hosted identity provider, name, content, and inclusion in the userinfo endpoint
# will most likely need to be configured.
alpine.oidc.teams.claim=groups
```

#### Proxy Configuration

Proxy support can be configured in one of two ways, using the proxy settings defined
in `application.properties` or through environment variables. By default, the system
will attempt to read the `https_proxy`, `http_proxy` and `no_proxy` environment variables. If one 
of these are set, Dependency-Track will use them automatically.

`no_proxy` specifies URLs that should be excluded from proxying.
This can be a comma-separated list of hostnames, domain names, or a mixture of both.
If a port number is specified for a URL, only the requests with that port number to that URL will be excluded from proxying.
`no_proxy` can also set to be a single asterisk ('*') to match all hosts.

Dependency-Track supports proxies that require BASIC, DIGEST, and NTLM authentication.

#### Logging Levels

Logging levels (INFO, WARN, ERROR, DEBUG, TRACE) can be specified by passing the level 
to the `dependencyTrack.logging.level` system property on startup. For example, the 
following command will start Dependency-Track (embedded) with DEBUG logging:

```bash
java -Xmx4G -DdependencyTrack.logging.level=DEBUG -jar dependency-track-embedded.war
```

For Docker deployments, simply set the `LOGGING_LEVEL` environment variable to one of
INFO, WARN, ERROR, DEBUG, or TRACE.

### Frontend

The frontend uses a static `config.json` file that is dynamically requested and evaluated via AJAX.
This file resides in `<BASE_URL>/static/config.json`.

#### Default configuration

```json
{
    // Required
    // The base URL of the API server.
    // NOTE:
    //   * This URL must be reachable by the browsers of your users.
    //   * The frontend container itself does NOT communicate with the API server directly, it just serves static files.
    //   * When deploying to dedicated servers, please use the external IP or domain of the API server.
    "API_BASE_URL": "",
    // Optional
    // Defines the issuer URL to be used for OpenID Connect.
    // See alpine.oidc.issuer property of the backend.
    "OIDC_ISSUER": "",
    // Optional
    // Defines the client ID for OpenID Connect.
    "OIDC_CLIENT_ID": "",
    // Optional
    // Defines the scopes to request for OpenID Connect.
    // See also: https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
    "OIDC_SCOPE": "openid profile email",
    // Optional
    // Specifies the OpenID Connect flow to use.
    // Values other than "implicit" will result in the Code+PKCE flow to be used.
    // Usage of the implicit flow is strongly discouraged, but may be necessary when
    // the IdP of choice does not support the Code+PKCE flow.
    // See also:
    //   - https://oauth.net/2/grant-types/implicit/
    //   - https://oauth.net/2/pkce/
    "OIDC_FLOW": "",
    // Optional
    // Defines the text of the OpenID Connect login button. 
    "OIDC_LOGIN_BUTTON_TEXT": ""
}
```

For containerized deployments, these settings can be overridden by either:

* mounting a customized `config.json` to `/app/static/config.json` inside the container
* providing them as environment variables

The names of the environment variables are equivalent to their counterparts in `config.json`.

> A mounted `config.json` takes precedence over environment variables. 
> If both are provided, environment variables will be ignored.
