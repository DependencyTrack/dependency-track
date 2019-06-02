---
title: LDAP Configuration
category: Getting Started
chapter: 1
order: 8
---

Dependency-Track has been tested with multiple LDAP servers. The following are
some example configurations that are known to work with the default schema of
each server implementation.

#### Microsoft Active Directory Example

```ini
alpine.ldap.enabled=true
alpine.ldap.server.url=ldap://ldap.example.com:3268
alpine.ldap.basedn=dc=example,dc=com
alpine.ldap.security.auth=simple
alpine.ldap.auth.username.format=%s@example.com
alpine.ldap.bind.username=cn=ServiceAccount,ou=Users,dc=example,dc=com
alpine.ldap.bind.password=mypassword
alpine.ldap.attribute.name=userPrincipalName
alpine.ldap.attribute.mail=mail
alpine.ldap.groups.filter=(&(objectClass=group)(objectCategory=Group))
alpine.ldap.user.groups.filter=(member:1.2.840.113556.1.4.1941:={USER_DN})
alpine.ldap.groups.search.filter=(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))
alpine.ldap.users.search.filter=(&(objectClass=user)(objectCategory=Person)(cn=*{SEARCH_TERM}*))
```

#### ApacheDS Example

```ini
alpine.ldap.enabled=true
alpine.ldap.server.url=ldap://ldap.example.com:389
alpine.ldap.basedn=dc=example,dc=com
alpine.ldap.security.auth=simple
alpine.ldap.auth.username.format=%s
alpine.ldap.bind.username=uid=ServiceAccount,ou=system
alpine.ldap.bind.password=mypassword
alpine.ldap.attribute.name=cn
alpine.ldap.attribute.mail=mail
alpine.ldap.groups.filter=(&(objectClass=groupOfUniqueNames))
alpine.ldap.user.groups.filter=(&(objectClass=groupOfUniqueNames)(uniqueMember={USER_DN}))
alpine.ldap.groups.search.filter=(&(objectClass=groupOfUniqueNames)(cn=*{SEARCH_TERM}*))
alpine.ldap.users.search.filter=(&(objectClass=inetOrgPerson)(cn=*{SEARCH_TERM}*))
```

#### Fedora 389 Directory Example

```ini
alpine.ldap.enabled=true
alpine.ldap.server.url=ldap://ldap.example.com:389
alpine.ldap.basedn=dc=example,dc=com
alpine.ldap.security.auth=simple
alpine.ldap.auth.username.format=%s
alpine.ldap.bind.username=cn=directory manager
alpine.ldap.bind.password=mypassword
alpine.ldap.attribute.name=uid
alpine.ldap.attribute.mail=mail
alpine.ldap.groups.filter=(&(objectClass=groupOfUniqueNames))
alpine.ldap.user.groups.filter=(&(objectClass=groupOfUniqueNames)(uniqueMember={USER_DN}))
alpine.ldap.groups.search.filter=(&(objectClass=groupOfUniqueNames)(cn=*{SEARCH_TERM}*))
alpine.ldap.users.search.filter=(&(objectClass=inetOrgPerson)(cn=*{SEARCH_TERM}*))
```

#### NetIQ/Novell eDirectory Example

```ini
alpine.ldap.enabled=true
alpine.ldap.server.url=ldaps://ldap.example.com:636
alpine.ldap.basedn=o=example
alpine.ldap.security.auth=simple
alpine.ldap.auth.username.format=%s
alpine.ldap.bind.username=cn=ServiceAccount,o=example
alpine.ldap.bind.password=mypassword
alpine.ldap.attribute.name=uid
alpine.ldap.attribute.mail=mail
alpine.ldap.groups.filter=(&(objectClass=groupOfUniqueNames))
alpine.ldap.user.groups.filter=(&(objectClass=groupOfUniqueNames)(uniqueMember={USER_DN}))
alpine.ldap.groups.search.filter=(&(objectClass=groupOfUniqueNames)(cn=*{SEARCH_TERM}*))
alpine.ldap.users.search.filter=(&(objectClass=inetOrgPerson)(cn=*{SEARCH_TERM}*))
```