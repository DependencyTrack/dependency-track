/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.filters;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.persistence.AlpineQueryManager;
import alpine.server.auth.PermissionRequired;
import alpine.server.auth.SessionTokenService;
import alpine.server.persistence.PersistenceManagerFactory;
import alpine.server.resources.AlpineResource;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class AuthorizationFilterTest extends JerseyTest {

    @Path("/")
    public static class TestResource extends AlpineResource {

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        @PermissionRequired(value = {"FOO", "BAR"})
        public Response get() {
            return Response.ok(Map.of(
                    "effectivePermissions",
                    getAlpineRequest().getEffectivePermissions())).build();
        }

        @GET
        @Path("/unprotected")
        @Produces(MediaType.APPLICATION_JSON)
        public Response getUnprotected() {
            return Response.ok(Map.of(
                    "effectivePermissions",
                    getAlpineRequest().getEffectivePermissions())).build();
        }

    }

    @AfterEach
    public void tearDown() throws Exception {
        PersistenceManagerFactory.tearDown();
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
    void shouldAllowCorsPreflightWithoutAuthentication() {
        final Response response = target("/unprotected")
                .request()
                .options();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void shouldPopulateEffectivePermissionsOnRequestsWithoutPermissionRequired() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Permission bazPermission = qm.createPermission("BAZ", null);

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(bazPermission);

            apiKey = qm.createApiKey(team).getKey();
        }

        final Response response = target("/unprotected")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ"]
                        }
                        """);
    }

    @Test
    void shouldRejectApiKeyRequestWithoutPermissions() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Team team = qm.createTeam("foo");

            apiKey = qm.createApiKey(team).getKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldRejectApiKeyRequestWithNoRequiredPermission() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(bazPermission);

            apiKey = qm.createApiKey(team).getKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldAllowApiKeyRequestWithAtLeastOneRequiredPermission() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(fooPermission);
            team.getPermissions().add(bazPermission);

            apiKey = qm.createApiKey(team).getKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldAllowApiKeyRequestWithAllRequiredPermissions() {
        final String apiKey;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission barPermission = qm.createPermission("BAR", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(fooPermission);
            team.getPermissions().add(barPermission);
            team.getPermissions().add(bazPermission);

            apiKey = qm.createApiKey(team).getKey();
        }

        final Response response = target("/")
                .request()
                .header("X-Api-Key", apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAR", "BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldRejectManagedUserRequestWithoutPermissions() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser managedUser = qm.createManagedUser("test", "test");

            bearerToken = new SessionTokenService().createSession(managedUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldRejectManagedUserRequestWithNoRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final ManagedUser managedUser = qm.createManagedUser("test", "test");
            managedUser.getPermissions().add(bazPermission);

            bearerToken = new SessionTokenService().createSession(managedUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldAllowManagedUserRequestWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final ManagedUser managedUser = qm.createManagedUser("test", "test");
            managedUser.getPermissions().add(fooPermission);
            managedUser.getPermissions().add(bazPermission);

            bearerToken = new SessionTokenService().createSession(managedUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldAllowManagedUserRequestWhenMemberOfTeamWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(fooPermission);

            final ManagedUser managedUser = qm.createManagedUser("test", "test");
            managedUser.getPermissions().add(bazPermission);
            managedUser.getTeams().add(team);

            bearerToken = new SessionTokenService().createSession(managedUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldRejectLdapUserRequestWithoutPermissions() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final LdapUser ldapUser = qm.createLdapUser("test");

            bearerToken = new SessionTokenService().createSession(ldapUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldRejectLdapUserRequestWithNoRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final LdapUser ldapUser = qm.createLdapUser("test");
            ldapUser.getPermissions().add(bazPermission);

            bearerToken = new SessionTokenService().createSession(ldapUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldAllowLdapUserRequestWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final LdapUser ldapUser = qm.createLdapUser("test");
            ldapUser.getPermissions().add(fooPermission);
            ldapUser.getPermissions().add(bazPermission);

            bearerToken = new SessionTokenService().createSession(ldapUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldAllowLdapUserRequestWhenMemberOfTeamWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(fooPermission);

            final LdapUser ldapUser = qm.createLdapUser("test");
            ldapUser.getPermissions().add(bazPermission);
            ldapUser.getTeams().add(team);

            bearerToken = new SessionTokenService().createSession(ldapUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldRejectOidcUserRequestWithoutPermissions() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final OidcUser oidcUser = qm.createOidcUser("test");

            bearerToken = new SessionTokenService().createSession(oidcUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldRejectOidcUserRequestWithNoRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final OidcUser oidcUser = qm.createOidcUser("test");
            oidcUser.getPermissions().add(bazPermission);

            bearerToken = new SessionTokenService().createSession(oidcUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldAllowOidcUserRequestWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final OidcUser oidcUser = qm.createOidcUser("test");
            oidcUser.getPermissions().add(fooPermission);
            oidcUser.getPermissions().add(bazPermission);

            bearerToken = new SessionTokenService().createSession(oidcUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

    @Test
    void shouldAllowOidcUserRequestWhenMemberOfTeamWithAtLeastOneRequiredPermission() {
        final String bearerToken;
        try (final var qm = new AlpineQueryManager()) {
            final Permission fooPermission = qm.createPermission("FOO", null);
            final Permission bazPermission = qm.createPermission("BAZ", null); // Non-required.

            final Team team = qm.createTeam("foo");
            team.getPermissions().add(fooPermission);

            final OidcUser oidcUser = qm.createOidcUser("test");
            oidcUser.getPermissions().add(bazPermission);
            oidcUser.getTeams().add(team);

            bearerToken = new SessionTokenService().createSession(oidcUser.getId());
        }

        final Response response = target("/")
                .request()
                .header("Authorization", "Bearer " + bearerToken)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "effectivePermissions": ["BAZ", "FOO"]
                        }
                        """);
    }

}
