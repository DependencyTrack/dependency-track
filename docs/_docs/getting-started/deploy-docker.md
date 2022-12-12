---
title: Deploying Docker Container
category: Getting Started
chapter: 1
order: 1
---

Deploying with Docker is the easiest and fastest method of getting started. No prerequisites are required
other than a modern version of Docker.

> The 'latest' tag in Docker Hub will always refer to the latest stable GA release. Consult the GitHub repo
> for instructions on how to run untested snapshot releases.

### Container Requirements (API Server)

| Minimum     | Recommended |
| :---------- | :---------- |
| 4.5GB RAM   | 16GB RAM    |
| 2 CPU cores | 4 CPU cores |

> These requirements can be disabled by setting the 'system.requirement.check.enabled' property or the 'SYSTEM_REQUIREMENT_CHECK_ENABLED' environment variable to 'false'. 

### Container Requirements (Front End)

| Minimum     | Recommended |
| :---------- | :---------- |
| 512MB RAM   | 1GB RAM    |
| 1 CPU cores | 2 CPU cores |

### Quickstart (Docker Compose)

```bash
# Downloads the latest Docker Compose file
curl -LO https://dependencytrack.org/docker-compose.yml

# Starts the stack using Docker Compose
docker-compose up -d
```

### Quickstart (Docker Swarm)

```bash
# Downloads the latest Docker Compose file
curl -LO https://dependencytrack.org/docker-compose.yml

# Initializes Docker Swarm (if not previously initialized)
docker swarm init

# Starts the stack using Docker Swarm
docker stack deploy -c docker-compose.yml dtrack
```

### Quickstart (Manual Execution)

```bash
# Pull the image from the Docker Hub OWASP repo
docker pull dependencytrack/bundled

# Creates a dedicated volume where data can be stored outside the container
docker volume create --name dependency-track

# Run the bundled container with 8GB RAM on port 8080
docker run -d -m 8192m -p 8080:8080 --name dependency-track -v dependency-track:/data dependencytrack/bundled
```

### Docker Compose (Automated / Orchestration)

The preferred method for production environments is to use docker-compose.yml with a corresponding
database container (Postgres, MySQL, or Microsoft SQL). The following is an example YAML file that
can be used with `docker-compose` or `docker stack deploy`.

```yaml
version: '3.7'

#####################################################
# This Docker Compose file contains two services
#    Dependency-Track API Server
#    Dependency-Track FrontEnd
#####################################################

volumes:
  dependency-track:

services:
  dtrack-apiserver:
    image: dependencytrack/apiserver
    # environment:
    # The Dependency-Track container can be configured using any of the
    # available configuration properties defined in:
    # https://docs.dependencytrack.org/getting-started/configuration/
    # All properties are upper case with periods replaced by underscores.
    #
    # Database Properties
    # - ALPINE_DATABASE_MODE=external
    # - ALPINE_DATABASE_URL=jdbc:postgresql://postgres10:5432/dtrack
    # - ALPINE_DATABASE_DRIVER=org.postgresql.Driver
    # - ALPINE_DATABASE_USERNAME=dtrack
    # - ALPINE_DATABASE_PASSWORD=changeme
    # - ALPINE_DATABASE_POOL_ENABLED=true
    # - ALPINE_DATABASE_POOL_MAX_SIZE=20
    # - ALPINE_DATABASE_POOL_MIN_IDLE=10
    # - ALPINE_DATABASE_POOL_IDLE_TIMEOUT=300000
    # - ALPINE_DATABASE_POOL_MAX_LIFETIME=600000
    #
    # Optional LDAP Properties
    # - ALPINE_LDAP_ENABLED=true
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
    # - ALPINE_LDAP_GROUPS_SEARCH_FILTER=(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))
    # - ALPINE_LDAP_USERS_SEARCH_FILTER=(&(objectClass=user)(objectCategory=Person)(cn=*{SEARCH_TERM}*))
    # - ALPINE_LDAP_USER_PROVISIONING=false
    # - ALPINE_LDAP_TEAM_SYNCHRONIZATION=false
    #
    # Optional OpenID Connect (OIDC) Properties
    # - ALPINE_OIDC_ENABLED=true
    # - ALPINE_OIDC_ISSUER=https://auth.example.com/auth/realms/example
    # - ALPINE_OIDC_USERNAME_CLAIM=preferred_username
    # - ALPINE_OIDC_TEAMS_CLAIM=groups
    # - ALPINE_OIDC_USER_PROVISIONING=true
    # - ALPINE_OIDC_TEAM_SYNCHRONIZATION=true
    #
    # Optional HTTP Proxy Settings
    # - ALPINE_HTTP_PROXY_ADDRESS=proxy.example.com
    # - ALPINE_HTTP_PROXY_PORT=8888
    # - ALPINE_HTTP_PROXY_USERNAME=
    # - ALPINE_HTTP_PROXY_PASSWORD=
    # - ALPINE_NO_PROXY=
    #
    # Optional HTTP Outbound Connection Timeout Settings. All values are in seconds.
    # - ALPINE_HTTP_TIMEOUT_CONNECTION=30
    # - ALPINE_HTTP_TIMEOUT_SOCKET=30
    # - ALPINE_HTTP_TIMEOUT_POOL=60
    #
    # Optional Cross-Origin Resource Sharing (CORS) Headers
    # - ALPINE_CORS_ENABLED=true
    # - ALPINE_CORS_ALLOW_ORIGIN=*
    # - ALPINE_CORS_ALLOW_METHODS=GET, POST, PUT, DELETE, OPTIONS
    # - ALPINE_CORS_ALLOW_HEADERS=Origin, Content-Type, Authorization, X-Requested-With, Content-Length, Accept, Origin, X-Api-Key, X-Total-Count, *
    # - ALPINE_CORS_EXPOSE_HEADERS=Origin, Content-Type, Authorization, X-Requested-With, Content-Length, Accept, Origin, X-Api-Key, X-Total-Count
    # - ALPINE_CORS_ALLOW_CREDENTIALS=true
    # - ALPINE_CORS_MAX_AGE=3600
    #
    # Optional metrics properties
    # - ALPINE_METRICS_ENABLED=true
    # - ALPINE_METRICS_AUTH_USERNAME=
    # - ALPINE_METRICS_AUTH_PASSWORD=
    #
    # Optional environmental variables to enable default notification publisher templates override and set the base directory to search for templates
    # - DEFAULT_TEMPLATES_OVERRIDE_ENABLED=false
    # - DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY=/data
    #
    # Optional configuration for the Snyk analyzer
    # - SNYK_THREAD_POOL_SIZE=10
    # - SNYK_RETRY_MAX_ATTEMPTS=6
    # - SNYK_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER=2
    # - SNYK_RETRY_EXPONENTIAL_BACKOFF_INITIAL_DURATION_SECONDS=1
    # - SNYK_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION_SECONDS=60
    #
    # Optional configuration for the OSS Index analyzer
    # - OSSINDEX_REQUEST_MAX_PURL=128
    # - OSSINDEX_RETRY_BACKOFF_MAX_ATTEMPTS=50
    # - OSSINDEX_RETRY_BACKOFF_MULTIPLIER=2
    # - OSSINDEX_RETRY_BACKOFF_MAX_DURATION=600000
    #
    # Optional configuration for the repository metadata analyzer cache stampede for high concurrency workloads
    # - REPO_META_ANALYZER_CACHESTAMPEDEBLOCKER_ENABLED=true
    # - REPO_META_ANALYZER_CACHESTAMPEDEBLOCKER_LOCK_BUCKETS=1000
    # - REPO_META_ANALYZER_CACHESTAMPEDEBLOCKER_MAX_ATTEMPTS=10
    #
    # Optional configuration for the system requirements
    # - SYSTEM_REQUIREMENT_CHECK_ENABLED=true
    # Optional environmental variables to provide more JVM arguments to the API Server JVM, i.e. "-XX:ActiveProcessorCount=8"
    # - EXTRA_JAVA_OPTIONS=
    
    deploy:
      resources:
        limits:
          memory: 12288m
        reservations:
          memory: 8192m
      restart_policy:
        condition: on-failure
    ports:
      - '8081:8080'
    volumes:
    # Optional volume mount to override default notification publisher templates
    # - "/host/path/to/template/base/dir:/data/templates"
      - 'dependency-track:/data'
    restart: unless-stopped

  dtrack-frontend:
    image: dependencytrack/frontend
    depends_on:
      - dtrack-apiserver
    environment:
      # The base URL of the API server.
      # NOTE:
      #   * This URL must be reachable by the browsers of your users.
      #   * The frontend container itself does NOT communicate with the API server directly, it just serves static files.
      #   * When deploying to dedicated servers, please use the external IP or domain of the API server.
      - API_BASE_URL=http://localhost:8081
      # - "OIDC_ISSUER="
      # - "OIDC_CLIENT_ID="
      # - "OIDC_SCOPE="
      # - "OIDC_FLOW="
      # - "OIDC_LOGIN_BUTTON_TEXT="
      # volumes:
      # - "/host/path/to/config.json:/app/static/config.json"
    ports:
      - "8080:8080"
    restart: unless-stopped
```

### Bundled JDBC Drivers

The following JDBC Drivers are included with Dependency-Track.

| Driver        | Class                                        |
| ------------- | -------------------------------------------- |
| Microsoft SQL | com.microsoft.sqlserver.jdbc.SQLServerDriver |
| MySQL         | com.mysql.jdbc.Driver                        |
| PostgreSQL    | org.postgresql.Driver                        |
