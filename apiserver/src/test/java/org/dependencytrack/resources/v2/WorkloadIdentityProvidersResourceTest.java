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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProvider;
import org.dependencytrack.auth.workloadidentity.WorkloadIdentityProviderDao;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class WorkloadIdentityProvidersResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    private static String publicJwks;

    @BeforeAll
    static void generatePublicJwks() throws Exception {
        publicJwks =
                new JWKSet(new RSAKeyGenerator(2048).keyID("key-1").generate().toPublicJWK()).toString();
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnCreatedForInlineKeys() throws Exception {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final RSAKey signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "github-actions",
                          "type": "OIDC",
                          "issuer": "https://token.actions.githubusercontent.com",
                          "audience": "https://dependency-track.example.com",
                          "jwks": %s
                        }
                        """.formatted(new JWKSet(signingKey.toPublicJWK()).toString())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getLocation().getPath()).endsWith("/workload-identity-providers/github-actions");
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnBadRequestForBlockedJwksUrl() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "github-actions",
                          "type": "OIDC",
                          "issuer": "https://token.actions.githubusercontent.com",
                          "audience": "https://dependency-track.example.com",
                          "jwks_url": "https://169.254.169.254/keys"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.detail").asString().contains("not allowed");
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnBadRequestWhenDiscoveryTargetIsBlocked() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "internal",
                          "type": "OIDC",
                          "issuer": "https://[fe80::1]",
                          "audience": "https://dependency-track.example.com"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.detail").asString().contains("not allowed");
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnBadRequestForSpiffeWithoutJwksUrl() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "spire",
                          "type": "SPIFFE",
                          "issuer": "example.org",
                          "audience": "https://dependency-track.example.com"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnBadRequestForSpiffeIssuerThatIsNotATrustDomain() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "spire",
                          "type": "SPIFFE",
                          "issuer": "spiffe://example.org",
                          "audience": "https://dependency-track.example.com",
                          "jwks": %s
                        }
                        """.formatted(publicJwks)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.detail").asString().contains("trust domain");
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnBadRequestWhenBothKeySourcesAreGiven() throws Exception {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        final RSAKey signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "github-actions",
                          "type": "OIDC",
                          "issuer": "https://token.actions.githubusercontent.com",
                          "audience": "https://dependency-track.example.com",
                          "jwks_url": "https://example.com/keys",
                          "jwks": %s
                        }
                        """.formatted(new JWKSet(signingKey.toPublicJWK()).toString())));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateWorkloadIdentityProviderShouldReturnBadRequestForNonHttpsJwksUrl() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);
        createProvider("github-actions");

        final Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "jwks_url": "http://example.com/keys"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void getWorkloadIdentityProviderShouldReturnProvider() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("github-actions");

        final Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "github-actions",
                  "type": "OIDC",
                  "issuer": "https://token.actions.githubusercontent.com",
                  "audience": "https://dependency-track.example.com",
                  "jwks_key_ids": [
                    "key-1"
                  ],
                  "session_lifetime_seconds": 3600,
                  "created_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    void getWorkloadIdentityProviderShouldReturnNotFoundWhenUnknown() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

        final Response response = jersey.target("/workload-identity-providers/nope")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void getWorkloadIdentityProviderShouldReturnForbiddenWithoutPermission() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        createProvider("github-actions");

        final Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void listWorkloadIdentityProvidersShouldKeepTheTotalAcrossPages() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("zeta");
        createProvider("alpha");

        Response response = jersey.target("/workload-identity-providers")
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
                      "type": "OIDC",
                      "issuer": "https://token.actions.githubusercontent.com",
                      "audience": "https://dependency-track.example.com",
                      "jwks_key_ids": [
                        "key-1"
                      ],
                      "session_lifetime_seconds": 3600,
                      "created_at": "${json-unit.any-number}"
                    }
                  ],
                  "next_page_token": "${json-unit.any-string}",
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """);

        response = jersey.target("/workload-identity-providers")
                .queryParam("limit", 1)
                .queryParam("page_token", responseJson.getString("next_page_token"))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final String secondPageJson = getPlainTextBody(response);
        assertThatJson(secondPageJson).inPath("$.items[*].name").isEqualTo(/* language=JSON */ """
                ["zeta"]
                """);
        assertThatJson(secondPageJson).inPath("$.total.count").isEqualTo(2);
    }

    @Test
    void listWorkloadIdentityProvidersShouldFilterByName() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("github-actions");
        createProvider("gitlab-ci");

        final Response response = jersey.target("/workload-identity-providers")
                .queryParam("q", "LAB")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items[*].name").isEqualTo(/* language=JSON */ """
                        ["gitlab-ci"]
                        """);
    }

    @Test
    void updateWorkloadIdentityProviderShouldChangeOnlyTheGivenFields() throws Exception {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE, Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("github-actions");

        final RSAKey signingKey = new RSAKeyGenerator(2048).keyID("key-2").generate();

        Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .method(
                        "PATCH",
                        Entity.json(
                                /* language=JSON */ """
                        {
                          "audience": "https://dtrack.example.org",
                          "jwks": %s,
                          "session_lifetime_seconds": 600
                        }
                        """.formatted(new JWKSet(signingKey.toPublicJWK()).toString())));
        assertThat(response.getStatus()).isEqualTo(204);

        response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "github-actions",
                  "type": "OIDC",
                  "issuer": "https://token.actions.githubusercontent.com",
                  "audience": "https://dtrack.example.org",
                  "jwks_key_ids": [
                    "key-2"
                  ],
                  "session_lifetime_seconds": 600,
                  "created_at": "${json-unit.any-number}"
                }
                """);
    }

    @Test
    void updateWorkloadIdentityProviderShouldChangeTheIssuerOfInlineKeyProviders() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE, Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("github-actions");

        Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "issuer": "https://github.example.com/_services/token"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);

        response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final String responseJson = getPlainTextBody(response);
        assertThatJson(responseJson).inPath("$.issuer").isEqualTo("https://github.example.com/_services/token");
        assertThatJson(responseJson).inPath("$.jwks_key_ids").isEqualTo(/* language=JSON */ """
                ["key-1"]
                """);
    }

    @Test
    void updateWorkloadIdentityProviderShouldRediscoverKeysWhenTheIssuerOfUrlKeyProvidersChanges() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE, Permissions.ACCESS_MANAGEMENT_READ);
        useJdbiTransaction(handle -> handle.attach(WorkloadIdentityProviderDao.class)
                .create(
                        "github-actions",
                        WorkloadIdentityProvider.Type.OIDC,
                        "https://token.actions.githubusercontent.com",
                        "https://dependency-track.example.com",
                        "https://token.actions.githubusercontent.com/.well-known/jwks",
                        /* jwks */ null,
                        3600));

        // Discovery of the new issuer is refused, because it points at a blocked address.
        Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "issuer": "https://127.0.0.1"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);

        response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.issuer")
                .isEqualTo("https://token.actions.githubusercontent.com");
    }

    @Test
    void updateWorkloadIdentityProviderShouldReturnBadRequestForSpiffeIssuerThatIsNotATrustDomain() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);
        useJdbiTransaction(handle -> handle.attach(WorkloadIdentityProviderDao.class)
                .create(
                        "spire",
                        WorkloadIdentityProvider.Type.SPIFFE,
                        "example.org",
                        "https://dependency-track.example.com",
                        /* jwksUrl */ null,
                        publicJwks,
                        3600));

        final Response response = jersey.target("/workload-identity-providers/spire")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "issuer": "spiffe://other.org"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).inPath("$.detail").asString().contains("trust domain");
    }

    @Test
    void updateWorkloadIdentityProviderShouldReturnNotFoundWhenUnknown() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        final Response response = jersey.target("/workload-identity-providers/nope")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "audience": "https://dtrack.example.org"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void deleteWorkloadIdentityProviderShouldRemoveIt() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE, Permissions.ACCESS_MANAGEMENT_READ);
        createProvider("github-actions");

        Response response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);

        response = jersey.target("/workload-identity-providers/github-actions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void deleteWorkloadIdentityProviderShouldReturnNotFoundWhenUnknown() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        final Response response = jersey.target("/workload-identity-providers/nope")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void createWorkloadIdentityProviderShouldReturnForbiddenWithoutPermission() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final RSAKey signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();

        final Response response = jersey.target("/workload-identity-providers")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "github-actions",
                          "type": "OIDC",
                          "issuer": "https://token.actions.githubusercontent.com",
                          "audience": "https://dependency-track.example.com",
                          "jwks": %s
                        }
                        """.formatted(new JWKSet(signingKey.toPublicJWK()).toString())));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    private static void createProvider(String name) {
        useJdbiTransaction(handle -> handle.attach(WorkloadIdentityProviderDao.class)
                .create(
                        name,
                        WorkloadIdentityProvider.Type.OIDC,
                        "https://token.actions.githubusercontent.com",
                        "https://dependency-track.example.com",
                        /* jwksUrl */ null,
                        publicJwks,
                        3600));
    }
}
