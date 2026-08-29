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
import alpine.model.Team;
import alpine.model.auth.TeamRef;
import alpine.model.auth.UserPrincipal;
import alpine.model.auth.UserType;
import alpine.persistence.AlpineQueryManager;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.testing.database.TestDatabaseExtension;
import org.glassfish.jersey.server.ContainerRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.Principal;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionTokenAuthenticationServiceTest {

    @RegisterExtension
    static final TestDatabaseExtension DATABASE = new TestDatabaseExtension();

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
    void shouldReturnSelfContainedPrincipal() throws Exception {
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            final OidcUser user = qm.callInTransaction(() -> {
                // NB: Use a non-ManagedUser here to ensure that DN
                // correctly resolves the user type via discriminator column.
                final OidcUser created = qm.createOidcUser("testuser");

                final Team team = qm.createTeam("team-a");
                qm.addUserToTeam(created, team);

                // BAR comes from the team, FOO directly, and FOO also from the team,
                // so the union has to collapse it rather than report it twice.
                final var foo = qm.createPermission("FOO", null);
                team.setPermissions(List.of(qm.createPermission("BAR", null), foo));
                created.setPermissions(List.of(foo));

                return created;
            });

            rawToken = new SessionTokenService().createSession(user.getId());
        }

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(request);

        final UserPrincipal principal = authService.authenticate();
        assertThat(principal).isNotNull();
        assertThat(principal.username()).isEqualTo("testuser");
        assertThat(principal.type()).isEqualTo(UserType.OIDC);
        assertThat(principal.teams()).extracting(TeamRef::name).containsExactly("team-a");
        assertThat(principal.effectivePermissions()).containsExactlyInAnyOrder("FOO", "BAR");
        assertThat(authService.isPortfolioAccessControlEnabled()).isFalse();
    }

    @Test
    void shouldNotThrowWhenNotSpecified() {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(null);

        final var authService = new SessionTokenAuthenticationService(request);
        assertThatNoException().isThrownBy(authService::authenticate);
    }

    @Test
    void shouldResolvePrincipalWithoutTeamsOrPermissions() throws Exception {
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            rawToken = new SessionTokenService()
                    .createSession(
                            qm.createManagedUser("lonely", "passwordHash").getId());
        }

        final UserPrincipal principal = authenticate(rawToken);

        assertThat(principal).isNotNull();
        assertThat(principal.teams()).isEmpty();
        assertThat(principal.effectivePermissions()).isEmpty();
    }

    @Test
    void shouldResolveEveryUserType() throws Exception {
        final String managedToken;
        final String ldapToken;
        final String oidcToken;
        try (final var qm = new AlpineQueryManager()) {
            final var sessionTokenService = new SessionTokenService();
            managedToken = sessionTokenService.createSession(
                    qm.createManagedUser("managed", "passwordHash").getId());
            ldapToken =
                    sessionTokenService.createSession(qm.createLdapUser("ldap").getId());
            oidcToken =
                    sessionTokenService.createSession(qm.createOidcUser("oidc").getId());
        }

        assertThat(authenticate(managedToken).type()).isEqualTo(UserType.MANAGED);
        assertThat(authenticate(ldapToken).type()).isEqualTo(UserType.LDAP);
        assertThat(authenticate(oidcToken).type()).isEqualTo(UserType.OIDC);
    }

    @Test
    void shouldThrowWhenPortfolioAccessControlIsQueriedBeforeAuthenticating() {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer whatever"));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(new SessionTokenAuthenticationService(request)::isPortfolioAccessControlEnabled);
    }

    @ParameterizedTest
    @CsvSource({"true,true", "TRUE,true", " true ,true", "1,true", "false,false", "0,false", "yes,false"})
    void shouldReportWhetherPortfolioAccessControlIsEnabled(String propertyValue, boolean expected) throws Exception {
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            rawToken = new SessionTokenService()
                    .createSession(
                            qm.createManagedUser("testuser", "passwordHash").getId());
        }
        executeUpdate(/* language=SQL */ """
            INSERT INTO "CONFIGPROPERTY" ("GROUPNAME", "PROPERTYNAME", "PROPERTYVALUE", "PROPERTYTYPE")
            VALUES ('access-management', 'acl.enabled', '%s', 'BOOLEAN')
            """.formatted(propertyValue));

        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(request);
        authService.authenticate();

        assertThat(authService.isPortfolioAccessControlEnabled()).isEqualTo(expected);
    }

    @Test
    void shouldAuthenticateWithASingleStatement() throws Exception {
        final String rawToken;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.callInTransaction(() -> {
                final ManagedUser created = qm.createManagedUser("testuser", "passwordHash");
                final Team team = qm.createTeam("team");
                team.setPermissions(List.of(qm.createPermission("PERM", null)));
                qm.addUserToTeam(created, team);
                return created;
            });
            rawToken = new SessionTokenService().createSession(user.getId());
        }

        final var statementCount = new AtomicInteger();
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        final var authService = new SessionTokenAuthenticationService(
                request,
                CountingDataSource.wrap(DataSourceRegistry.getInstance().getDefault(), statementCount));

        assertThat(authService.authenticate()).isNotNull();
        assertThat(statementCount.get()).isEqualTo(1);
    }

    private static UserPrincipal authenticate(String rawToken) throws Exception {
        final var request = mock(ContainerRequest.class);
        when(request.getRequestHeader("Authorization")).thenReturn(List.of("Bearer " + rawToken));
        return new SessionTokenAuthenticationService(request).authenticate();
    }

    private static void executeUpdate(String sql) throws SQLException {
        try (final Connection connection =
                        DataSourceRegistry.getInstance().getDefault().getConnection();
                final Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
    }
}
