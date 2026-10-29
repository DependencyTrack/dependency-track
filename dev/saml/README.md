# SAML test environment

Runs Dependency-Track with SAML login against a local Keycloak acting as identity provider.

## Start

Build the images from the feature branches first:

```shell
# In this repository (JDK 25):
mvn -T1 -Pquick install
docker build -t ghcr.io/dependencytrack/apiserver:saml-local -f apiserver/src/main/docker/Dockerfile apiserver

# In the frontend repository:
npm ci && npm run build
docker build -t ghcr.io/dependencytrack/frontend:saml-local -f docker/Dockerfile.alpine .
```

Then start the environment:

```shell
docker compose -f dev/saml/compose.yaml up -d
```

| Service         | URL                                                                     | Login         |
|:----------------|:------------------------------------------------------------------------|:--------------|
| Frontend        | http://localhost:8088                                                   | see below     |
| API server      | http://localhost:8080                                                   |               |
| SP metadata     | http://localhost:8080/api/v2/saml/metadata                              |               |
| Keycloak admin  | http://localhost:8180/admin/master/console/#/dtrack                     | admin / admin |

## Users

| Keycloak user | Password | Groups                 |
|:--------------|:---------|:-----------------------|
| alice         | alice    | DT-Admins, DT-Auditors |
| bob           | bob      | DT-Auditors            |
| carol         | carol    | none                   |

The local Dependency-Track administrator is `admin` / `admin` (password change on first login).
Use the "More options" link on the login page to log in with it.

## Things to try

1. Log in as `alice` via "Login with Keycloak (SAML)". User provisioning creates the SAML user,
   and group provisioning creates the groups `DT-Admins` and `DT-Auditors`.
   Alice has no permissions yet, so the login stops with "permission required".
2. Log in as `admin`. Under Administration, Access Management:
   * SAML Users lists `alice`.
   * SAML Groups lists both groups. Map `DT-Admins` to the team `Administrators`.
3. Log in as `alice` again. Team synchronization adds her to `Administrators`, and the login succeeds.
4. Remove `alice` from `DT-Admins` in Keycloak, and log in again. She is removed from the team.

Set `DT_SAML_USER_PROVISIONING: "false"` in `compose.yaml` to see the error for unknown users.

## Stop

```shell
docker compose -f dev/saml/compose.yaml down -v
```
