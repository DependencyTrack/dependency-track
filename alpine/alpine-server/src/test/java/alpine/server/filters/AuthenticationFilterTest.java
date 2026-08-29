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
package alpine.server.filters;

import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.ManagedUser;
import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.Principal;
import alpine.model.auth.TeamRef;
import alpine.model.auth.UserPrincipal;
import alpine.persistence.AlpineQueryManager;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.SessionTokenService;
import alpine.server.resources.AlpineResource;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.junit.jupiter.api.AfterEach;
import org.dependencytrack.testing.database.TestDatabaseExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationFilterTest extends JerseyTest {

    @RegisterExtension
    static final TestDatabaseExtension DATABASE = new TestDatabaseExtension();

    @Path("/")
    public static class TestResource extends AlpineResource {

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public Response get() {
            final var principal = (Principal) getPrincipal();
            final String kind = switch (principal) {
                case ApiKeyPrincipal _ -> "apiKey";
                case UserPrincipal user -> user.type().name();
            };

            return Response.ok(Map.of(
                            "principalKind", kind,
                            "principalName", principal.getName(),
                            "principalTeams",
                                    principal.teams().stream().map(TeamRef::name).toList(),
                            "principalPermissions", principal.effectivePermissions()))
                    .build();
        }

        @GET
        @Path("/anonymous")
        @Produces(MediaType.APPLICATION_JSON)
        @AuthenticationNotRequired
        public Response getAnonymous() {
            return Response.ok(Map.of("ok", true)).build();
        }

    }

    @AfterEach
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Override
    protected Application configure() {
        forceSet(TestProperties.CONTAINER_PORT, "0");
        return new ResourceConfig(TestResource.class)
                .register(AuthFeature.class)
                .register(ApiFilter.class);
    }

    @Test
    void shouldRejectRequestWithoutCredentials() {
        final Response response = target("/").request().get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldAllowRequestWithoutCredentialsWhenAuthenticationNotRequired() {
        final Response response = target("/anonymous").request().get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void shouldAllowCorsPreflightWithoutCredentials() {
        final Response response = target("/").request().options();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void shouldRejectUnknownApiKey() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("foo");
            apiKey = qm.createApiKey(team).getKey();
        }

        // Keep the format valid, but flip the last character of the secret.
        final char lastChar = apiKey.charAt(apiKey.length() - 1);
        final String tamperedKey = apiKey.substring(0, apiKey.length() - 1) + (lastChar == 'a' ? 'b' : 'a');

        final Response response =
                target("/").request().header("X-Api-Key", tamperedKey).get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldRejectMalformedApiKey() {
        final Response response =
                target("/").request().header("X-Api-Key", "not-an-api-key").get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldRejectUnknownSessionToken() {
        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer not-a-valid-token")
                .get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldRejectExpiredSessionToken() throws Exception {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("testuser", "password");
            bearerToken = new SessionTokenService().createSession(user.getId());
        }

        expireAllSessions();

        final Response response =
                target("/").request().header("Authorization", "Bearer " + bearerToken).get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    private static void expireAllSessions() throws SQLException {
        try (final var qm = new AlpineQueryManager()) {
            final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
            try (final Statement statement =
                    ((Connection) jdoConnection.getNativeConnection()).createStatement()) {
                statement.executeUpdate(
                        "UPDATE \"USER_SESSION\" SET \"EXPIRES_AT\" = TIMESTAMP '2000-01-01 00:00:00'");
            } finally {
                jdoConnection.close();
            }
        }
    }

    @Test
    void shouldRejectSessionTokenOfSuspendedUser() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("testuser", "password");
            bearerToken = new SessionTokenService().createSession(user.getId());
            user.setSuspended(true);
        }

        final Response response =
                target("/").request().header("Authorization", "Bearer " + bearerToken).get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldPreferSessionTokenOverApiKeyWhenBothAreAsserted() {
        final String apiKey;
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("foo");
            apiKey = qm.createApiKey(team).getKey();

            final ManagedUser user = qm.createManagedUser("testuser", "password");
            bearerToken = new SessionTokenService().createSession(user.getId());
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.readEntity(String.class)).contains("\"principalKind\":\"MANAGED\"");
    }

    @Test
    void shouldRejectWhenApiKeyIsValidButSessionTokenIsNot() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("foo");
            apiKey = qm.createApiKey(team).getKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .header("Authorization", "Bearer not-a-valid-token")
                .get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldAuthenticateApiKeyAndExposeItsTeamsOrderedByName() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team charlie = qm.createTeam("charlie");
            final Team alpha = qm.createTeam("alpha");
            final Team bravo = qm.createTeam("bravo");

            final ApiKey createdApiKey = qm.createApiKey(charlie);
            createdApiKey.getTeams().add(bravo);
            createdApiKey.getTeams().add(alpha);
            apiKey = createdApiKey.getKey();
        }

        final Response response =
                target("/").request().header("X-Api-Key", apiKey).get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .isEqualTo(/* language=JSON */ """
                        {
                          "principalKind": "apiKey",
                          "principalName": "${json-unit.ignore}",
                          "principalTeams": ["alpha", "bravo", "charlie"],
                          "principalPermissions": []
                        }
                        """);
    }

    @Test
    void shouldAuthenticateUserAndExposeItsTeamsOrderedByName() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Team charlie = qm.createTeam("charlie");
            final Team alpha = qm.createTeam("alpha");
            final Team bravo = qm.createTeam("bravo");

            final ManagedUser user = qm.createManagedUser("testuser", "password");
            user.getTeams().add(charlie);
            user.getTeams().add(bravo);
            user.getTeams().add(alpha);

            bearerToken = new SessionTokenService().createSession(user.getId());
        }

        final Response response =
                target("/").request().header("Authorization", "Bearer " + bearerToken).get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .isEqualTo(/* language=JSON */ """
                        {
                          "principalKind": "MANAGED",
                          "principalName": "testuser",
                          "principalTeams": ["alpha", "bravo", "charlie"],
                          "principalPermissions": []
                        }
                        """);
    }

}
