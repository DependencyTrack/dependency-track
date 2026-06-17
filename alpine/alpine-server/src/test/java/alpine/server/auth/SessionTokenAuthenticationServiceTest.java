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
package alpine.server.auth;

import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import alpine.persistence.AlpineQueryManager;
import alpine.server.persistence.PersistenceManagerFactory;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.glassfish.jersey.server.ContainerRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionTokenAuthenticationServiceTest {

    @AfterEach
    void tearDown() {
        PersistenceManagerFactory.tearDown();
    }

    @Test
    void shouldAuthenticateWithValidSessionToken() throws Exception {
        final ManagedUser user;
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            user = qm.createManagedUser("testuser", "password");
            rawToken = new SessionTokenService().createSession(user.getId());
        }

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(request);

        assertThat(authService.isSpecified()).isTrue();
        final Principal principal = authService.authenticate();
        assertThat(principal).isNotNull();
        assertThat(principal.getName()).isEqualTo("testuser");
        assertThat(authService.getTokenHash()).isNotNull();
    }

    @Test
    void shouldReturnNullForInvalidToken() throws Exception {
        try (final var qm = new AlpineQueryManager()) {
            qm.createManagedUser("testuser", "password");
        }

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer not-a-valid-token"));
        final var authService = new SessionTokenAuthenticationService(request);

        assertThat(authService.isSpecified()).isTrue();
        assertThat(authService.authenticate()).isNull();
        assertThat(authService.getTokenHash()).isNull();
    }

    @Test
    void shouldReturnNullForExpiredSession() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of("dt.auth.session-timeout-ms", "1"))
                .build();
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("testuser", "password");
            rawToken = new SessionTokenService(config).createSession(user.getId());
        }

        Thread.sleep(50);

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(request);

        assertThat(authService.authenticate()).isNull();
    }

    @Test
    void shouldReturnNullForSuspendedManagedUser() throws Exception {
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("testuser", "password");
            rawToken = new SessionTokenService().createSession(user.getId());
            user.setSuspended(true);
        }

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(request);

        assertThat(authService.authenticate()).isNull();
        assertThat(authService.getTokenHash()).isNull();
    }

    @Test
    void shouldNotBeSpecifiedWhenNoAuthorizationHeader() {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(null);

        final var authService = new SessionTokenAuthenticationService(request);
        assertThat(authService.isSpecified()).isFalse();
    }

    @Test
    void shouldNotBeSpecifiedForNonBearerAuth() {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Basic dXNlcjpwYXNz"));

        final var authService = new SessionTokenAuthenticationService(request);
        assertThat(authService.isSpecified()).isFalse();
    }

    @Test
    void shouldAuthenticateRegardlessOfBearerSchemeCasing() throws Exception {
        final ManagedUser user;
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            user = qm.createManagedUser("testuser", "password");
            rawToken = new SessionTokenService().createSession(user.getId());
        }

        for (final String prefix : List.of("Bearer ", "bearer ", "BEARER ", "BeArEr ")) {
            final var request = mock(ContainerRequest.class);
            when(request.getRequestHeader("Authorization")).thenReturn(List.of(prefix + rawToken));
            final var authService = new SessionTokenAuthenticationService(request);

            assertThat(authService.isSpecified()).isTrue();
            final Principal principal = authService.authenticate();
            assertThat(principal).isNotNull();
            assertThat(principal.getName()).isEqualTo("testuser");
        }
    }

    @Test
    void shouldReturnNullWhenBearerValueIsEmpty() throws Exception {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer "));
        final var authService = new SessionTokenAuthenticationService(request);

        assertThat(authService.isSpecified()).isTrue();
        assertThat(authService.authenticate()).isNull();
    }

    @Test
    void shouldReturnDetachedUserWithTeamsAndPermissionsLoaded() throws Exception {
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            final OidcUser user = qm.callInTransaction(() -> {
                // NB: Use a non-ManagedUser here to ensure that DN
                // correctly resolves the user type via discriminator column.
                final OidcUser created = qm.createOidcUser("testuser");

                final Team team = qm.createTeam("team-a");
                qm.addUserToTeam(created, team);

                final Permission permission = qm.createPermission("FOO", null);
                created.setPermissions(List.of(permission));

                return created;
            });

            rawToken = new SessionTokenService().createSession(user.getId());
        }

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(request);

        final Principal principal = authService.authenticate();
        assertThat(principal).isInstanceOf(User.class);

        final var user = (User) principal;
        assertThat(user.getTeams())
                .extracting(Team::getName)
                .containsExactly("team-a");
        assertThat(user.getPermissions())
                .extracting(Permission::getName)
                .containsExactly("FOO");
    }

    @Test
    void shouldNotThrowWhenNotSpecified() {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(null);

        final var authService = new SessionTokenAuthenticationService(request);
        assertThatNoException().isThrownBy(authService::authenticate);
    }

}