/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v2;

import alpine.model.ApiKey;
import alpine.model.ServiceAccount;
import alpine.model.Team;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao.ServiceAccountDetailsRow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ServiceAccountsResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    @Test
    void createServiceAccountShouldPrefixTheUsernameAndReturnCreated() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "ci-pipeline",
                          "email": "ci@example.com"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation().getPath()).endsWith("/service-accounts/ci-pipeline");

        final ServiceAccountDetailsRow createdServiceAccount =
                withJdbiHandle(handle -> handle.attach(ServiceAccountDao.class).getByUsername("svc-ci-pipeline"));
        assertThat(createdServiceAccount).isNotNull().satisfies(account -> {
            assertThat(account.email()).isEqualTo("ci@example.com");
            assertThat(account.suspended()).isFalse();
        });
    }

    @ParameterizedTest
    @CsvSource({"svc-foo, 400", "SVC-foo, 400", "Svc-foo, 400", "svc, 201", "svcfoo, 201", "svc_foo, 201"})
    void createServiceAccountShouldRejectNamesWithTheReservedPrefix(String name, int expectedStatus) {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "%s"
                        }
                        """.formatted(name)));
        assertThat(response.getStatus()).isEqualTo(expectedStatus);
    }

    @Test
    void createServiceAccountShouldReturnConflictWhenNameIsTaken() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);
        createServiceAccount("ci-pipeline");

        final Response response = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "ci-pipeline"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
    }

    @Test
    void createServiceAccountShouldReturnForbiddenWithoutPermission() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "ci-pipeline"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void getServiceAccountShouldReturnTheAccount() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci-pipeline");

        final ServiceAccount serviceAccount = qm.getServiceAccount("svc-ci-pipeline");
        serviceAccount.setPermissions(List.of(qm.createPermission(Permissions.BOM_UPLOAD.name(), null)));
        qm.persist(serviceAccount);
        final Team team = qm.createTeam("Pirates");
        qm.addUserToTeam(serviceAccount, team);

        final Response response = jersey.target("/service-accounts/ci-pipeline")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "ci-pipeline",
                  "username": "svc-ci-pipeline",
                  "suspended": false,
                  "teams": [
                    {
                      "uuid": "%s",
                      "name": "Pirates"
                    }
                  ],
                  "permissions": [
                    "BOM_UPLOAD"
                  ]
                }
                """.formatted(team.getUuid()));
    }

    @Test
    void getServiceAccountShouldReturnEmptyTeamsAndPermissionsWhenThereAreNone() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci-pipeline");

        final Response response = jersey.target("/service-accounts/ci-pipeline")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "ci-pipeline",
                  "username": "svc-ci-pipeline",
                  "suspended": false,
                  "teams": [],
                  "permissions": []
                }
                """);
    }

    @Test
    void getServiceAccountShouldReturnNotFoundWhenUnknown() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

        final Response response = jersey.target("/service-accounts/nope")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void listServiceAccountsShouldKeepTheTotalAcrossPages() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("zeta");
        createServiceAccount("alpha");

        Response response = jersey.target("/service-accounts")
                .queryParam("limit", 1)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "name": "alpha",
                      "username": "svc-alpha",
                      "suspended": false
                    }
                  ],
                  "next_page_token": "${json-unit.any-string}",
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """);

        response = jersey.target("/service-accounts")
                .queryParam("limit", 1)
                .queryParam("page_token", responseJson.getString("next_page_token"))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "name": "zeta",
                      "username": "svc-zeta",
                      "suspended": false
                    }
                  ],
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void updateServiceAccountShouldClearTheEmailWhenGivenAnEmptyString() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);
        useJdbiHandle(handle -> handle.attach(ServiceAccountDao.class).create("svc-ci-pipeline", "ci@example.com"));

        final Response response = jersey.target("/service-accounts/ci-pipeline")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "email": ""
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(withJdbiHandle(
                                handle -> handle.attach(ServiceAccountDao.class).getByUsername("svc-ci-pipeline"))
                        .email())
                .isNull();
    }

    @Test
    void updateServiceAccountShouldReturnNotFoundWhenUnknown() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        final Response response = jersey.target("/service-accounts/ci-pipeline")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "suspended": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void createServiceAccountApiKeyShouldReturnConflictWhenAccountIsSuspended() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);
        createServiceAccount("ci-pipeline");
        useJdbiHandle(handle -> handle.attach(ServiceAccountDao.class).update("svc-ci-pipeline", null, true));

        final Response response = jersey.target("/service-accounts/ci-pipeline/api-keys")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("{}"));
        assertThat(response.getStatus()).isEqualTo(409);
    }

    @Test
    void deleteServiceAccountShouldRemoveItAndItsApiKeys() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE, Permissions.ACCESS_MANAGEMENT_CREATE);
        createServiceAccount("ci-pipeline");
        qm.createApiKey(qm.getServiceAccount("svc-ci-pipeline"), null).getPublicId();

        final Response response = jersey.target("/service-accounts/ci-pipeline")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);

        final ServiceAccountDetailsRow deletedServiceAccount =
                withJdbiHandle(handle -> handle.attach(ServiceAccountDao.class).getByUsername("svc-ci-pipeline"));
        assertThat(deletedServiceAccount).isNull();
        final long remainingKeys = withJdbiHandle(handle -> handle.createQuery(
                        /* language=SQL */ "SELECT COUNT(*) FROM \"APIKEY\" WHERE \"USER_ID\" IS NOT NULL")
                .mapTo(long.class)
                .one());
        assertThat(remainingKeys).isZero();
    }

    @Test
    void createServiceAccountApiKeyShouldReturnThePlainTextKeyOnce() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE, Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci-pipeline");

        final Response createResponse = jersey.target("/service-accounts/ci-pipeline/api-keys")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "comment": "for the build"
                        }
                        """));
        assertThat(createResponse.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(createResponse)).isEqualTo(/* language=JSON */ """
                {
                  "public_id": "${json-unit.any-string}",
                  "key": "${json-unit.any-string}"
                }
                """);

        final Response listResponse = jersey.target("/service-accounts/ci-pipeline/api-keys")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(listResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(listResponse)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "public_id": "${json-unit.any-string}",
                      "comment": "for the build",
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void listServiceAccountApiKeysShouldPaginateNewestFirst() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci-pipeline");
        final String olderPublicId =
                qm.createApiKey(qm.getServiceAccount("svc-ci-pipeline"), null).getPublicId();
        final String newerPublicId =
                qm.createApiKey(qm.getServiceAccount("svc-ci-pipeline"), null).getPublicId();

        Response response = jersey.target("/service-accounts/ci-pipeline/api-keys")
                .queryParam("limit", 1)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "public_id": "%s",
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "next_page_token": "${json-unit.any-string}",
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """.formatted(newerPublicId));

        final String nextPageToken = responseJson.getString("next_page_token");
        response = jersey.target("/service-accounts/ci-pipeline/api-keys")
                .queryParam("limit", 1)
                .queryParam("page_token", nextPageToken)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "public_id": "%s",
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """.formatted(olderPublicId));
    }

    @Test
    void createServiceAccountApiKeyShouldReturnNotFoundWhenAccountIsUnknown() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/service-accounts/nope/api-keys")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ "{}"));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void deleteServiceAccountApiKeyShouldReturnNoContent() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE, Permissions.ACCESS_MANAGEMENT_DELETE);
        createServiceAccount("ci-pipeline");
        final String publicId =
                qm.createApiKey(qm.getServiceAccount("svc-ci-pipeline"), null).getPublicId();

        final Response response = jersey.target("/service-accounts/ci-pipeline/api-keys/" + publicId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);

        final Response repeatResponse = jersey.target("/service-accounts/ci-pipeline/api-keys/" + publicId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(repeatResponse.getStatus()).isEqualTo(404);
    }

    @Test
    void deleteServiceAccountApiKeyShouldReturnNotFoundForKeyOfAnotherServiceAccount() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);
        createServiceAccount("ci-pipeline");
        createServiceAccount("other");
        final String otherPublicId =
                qm.createApiKey(qm.getServiceAccount("svc-other"), null).getPublicId();

        final Response response = jersey.target("/service-accounts/ci-pipeline/api-keys/" + otherPublicId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(qm.getApiKeyByPublicId(otherPublicId)).isNotNull();
    }

    @Test
    void deleteServiceAccountApiKeyShouldReturnNotFoundForTeamKey() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);
        createServiceAccount("ci-pipeline");
        final String teamPublicId = qm.createApiKey(qm.createTeam("builders")).getPublicId();

        final Response response = jersey.target("/service-accounts/ci-pipeline/api-keys/" + teamPublicId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(qm.getApiKeyByPublicId(teamPublicId)).isNotNull();
    }

    @Test
    void listServiceAccountsShouldNotMatchTheFilterAgainstTheReservedPrefix() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci-pipeline");

        final Response response = jersey.target("/service-accounts")
                .queryParam("q", "svc")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(parseJsonObject(response).getJsonArray("items")).isEmpty();
    }

    @Test
    void listServiceAccountsShouldTreatWildcardsInTheFilterLiterally() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci_bot");
        createServiceAccount("cibot");

        final Response response = jersey.target("/service-accounts")
                .queryParam("q", "_")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(parseJsonObject(response).getJsonArray("items"))
                .extracting(item -> item.asJsonObject().getString("name"))
                .containsExactly("ci_bot");
    }

    @Test
    void issuedApiKeyShouldAuthenticateAndAuthorizeAsTheServiceAccount() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createServiceAccount("ci-pipeline");
        final ApiKey serviceAccountKey = qm.createApiKey(qm.getServiceAccount("svc-ci-pipeline"), null);

        final Response forbiddenResponse = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, serviceAccountKey.getKey())
                .get();
        assertThat(forbiddenResponse.getStatus()).isEqualTo(403);

        final ServiceAccount serviceAccount = qm.getServiceAccount("svc-ci-pipeline");
        serviceAccount.setPermissions(List.of(qm.getPermission(Permissions.ACCESS_MANAGEMENT_READ.name())));
        qm.persist(serviceAccount);

        final Response okResponse = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, serviceAccountKey.getKey())
                .get();
        assertThat(okResponse.getStatus()).isEqualTo(200);
    }

    @Test
    void issuedApiKeyShouldStopWorkingWhenTheServiceAccountIsSuspended() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ, Permissions.ACCESS_MANAGEMENT_UPDATE);
        createServiceAccount("ci-pipeline");
        final ServiceAccount serviceAccount = qm.getServiceAccount("svc-ci-pipeline");
        serviceAccount.setPermissions(List.of(qm.getPermission(Permissions.ACCESS_MANAGEMENT_READ.name())));
        qm.persist(serviceAccount);
        final ApiKey serviceAccountKey = qm.createApiKey(qm.getServiceAccount("svc-ci-pipeline"), null);

        final Response suspendResponse = jersey.target("/service-accounts/ci-pipeline")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "suspended": true
                        }
                        """));
        assertThat(suspendResponse.getStatus()).isEqualTo(204);

        final Response response = jersey.target("/service-accounts")
                .request()
                .header(X_API_KEY, serviceAccountKey.getKey())
                .get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    private static void createServiceAccount(String name) {
        useJdbiHandle(handle -> handle.attach(ServiceAccountDao.class).create(ServiceAccount.usernameOf(name), null));
    }
}
