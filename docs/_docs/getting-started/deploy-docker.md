---
title: Deploying Docker Container
category: Getting Started
chapter: 1
order: 1
---

Deploying with Docker is the easiest and fastest method of getting started. No prerequisites are required
other than an modern version of Docker. 

> The 'latest' tag in Docker Hub will always refer to the latest stable GA release. Consult the GitHub repo
> for instructions on how to run untested snapshot releases.

### Quickstart (Manual Execution)

```bash
# Pull the image from the Docker Hub OWASP repo
docker pull owasp/dependency-track

# Creates a dedicated volume where data can be stored outside the container
docker volume create --name dependency-track

# Run the container
docker run -d -p 8080:8080 --name dependency-track -v dependency-track:/data owasp/dependency-track
```

### Docker Compose (Automated / Orchestration)

The preferred method for production environments is to use docker-compose.yml with a corresponding
database container (Postgres, MySQL, or Microsoft SQL). The following is an example YAML file that
can be used with `docker-compose` or `docker stack deploy`.

```yaml
version: '3'
services:
  dtrack:
    #environment:
    # The Dependency-Track container can be configured using any of the
    # available configuration properties defined in:
    # https://docs.dependencytrack.org/getting-started/configuration/
    # All properties are upper case with periods replaced by underscores.
    #
    # Database Properties
    # - ALPINE_DATABASE_MODE=external
    # - ALPINE_DATABASE_URL=jdbc:postgresql://postgres10:5432/dtrack
    # - ALPINE_DATABASE_DRIVER=org.postgresql.Driver
    # - ALPINE_DATABASE_DRIVER_PATH=/extlib/postgresql-42.2.5.jar
    # - ALPINE_DATABASE_USERNAME=dtrack
    # - ALPINE_DATABASE_PASSWORD=changeme
    #
    # Optional LDAP Properties
    # - ALPINE_LDAP_ENABLED=
    # - ALPINE_LDAP_SERVER_URL=ldap://ldap.example.com:389
    # - ALPINE_LDAP_BASEDN=dc=example,dc=com
    # - ALPINE_LDAP_SECURITY_AUTH=simple
    # - ALPINE_LDAP_BIND_USERNAME=
    # - ALPINE_LDAP_BIND_PASSWORD=
    # - ALPINE_LDAP_AUTH_USERNAME_FORMAT=%s@example.com
    # - ALPINE_LDAP_ATTRIBUTE_NAME=userPrincipalName
    # - ALPINE_LDAP_ATTRIBUTE_MAIL=mail
    # - ALPINE_LDAP_GROUPS_FILTER=(&(objectClass=group)(objectCategory=Group))
    # - ALPINE_LDAP_USER_GROUPS_FILTER=(member:1.2.840.113556.1.4.1941:={USER_DN})
    # - ALPINE_LDAP_USER_PROVISIONING=false
    # - ALPINE_LDAP_TEAM_SYNCHRONIZATION=false
    #
    # Optional HTTP Proxy Settings
    # - ALPINE_HTTP_PROXY_ADDRESS=proxy.example.com
    # - ALPINE_HTTP_PROXY_PORT=8888
    # - ALPINE_HTTP_PROXY_USERNAME=
    # - ALPINE_HTTP_PROXY_PASSWORD=
    image: 'owasp/dependency-track'
    ports:
    - '80:8080'
    volumes:
    - './data:/data'
```

### Bundled JDBC Drivers

JDBC Drivers are included with Dependency-Track (Docker only). They can be specified 
with `ALPINE_DATABASE_DRIVER_PATH`.

| Driver        | Path                                      |
| ------------- | ----------------------------------------- |
| Microsoft SQL | /extlib/mssql-jdbc-7.1.3.jre8-preview.jar |
| MySQL         | /extlib/mysql-connector-java-5.1.47.jar   |
| PostgreSQL    | /extlib/postgresql-42.2.5.jar             |

The inclusion of drivers does not preclude the use of other driver versions. They are
bundled as a matter of convenience.