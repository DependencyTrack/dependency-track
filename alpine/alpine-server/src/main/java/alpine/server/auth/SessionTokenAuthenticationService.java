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

import alpine.model.auth.UserPrincipal;
import alpine.model.auth.UserType;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.glassfish.jersey.server.ContainerRequest;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.core.HttpHeaders;

import javax.naming.AuthenticationException;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * @since 5.0.0
 */
@NullMarked
public final class SessionTokenAuthenticationService implements AuthenticationService<UserPrincipal> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionTokenAuthenticationService.class);
    private static final String LOOKUP_QUERY = /* language=SQL */ """
        WITH usr AS (
          SELECT u."ID"
               , u."USERNAME"
               , u."TYPE"
               , COALESCE(u."SUSPENDED", FALSE) AS "SUSPENDED"
            FROM "USER_SESSION" AS us
           INNER JOIN "USER" AS u
              ON u."ID" = us."USER_ID"
           WHERE us."TOKEN_HASH" = ?
             AND us."EXPIRES_AT" > NOW()
        )
        SELECT usr."ID" AS id
             , usr."USERNAME" AS username
             , usr."TYPE" AS type
             , usr."SUSPENDED" AS suspended
             , (
                 SELECT EXISTS (
                   SELECT 1
                     FROM "CONFIGPROPERTY" AS cp
                    WHERE cp."GROUPNAME" = 'access-management'
                      AND cp."PROPERTYNAME" = 'acl.enabled'
                      AND LOWER(TRIM(cp."PROPERTYVALUE")) IN ('true', '1')
                 )
               ) AS acl_enabled
             , teams.ids AS team_ids
             , teams.names AS team_names
             , teams.uuids AS team_uuids
             , (
                 SELECT ARRAY_AGG(DISTINCT p."NAME")
                   FROM "PERMISSION" AS p
                  WHERE p."ID" IN (
                    SELECT up."PERMISSION_ID"
                      FROM "USERS_PERMISSIONS" AS up
                     WHERE up."USER_ID" = usr."ID"
                     UNION
                    SELECT tp."PERMISSION_ID"
                      FROM "USERS_TEAMS" AS ut
                     INNER JOIN "TEAMS_PERMISSIONS" AS tp
                        ON tp."TEAM_ID" = ut."TEAM_ID"
                     WHERE ut."USER_ID" = usr."ID"
                  )
               ) AS permissions
          FROM usr
          LEFT JOIN LATERAL (
            SELECT ARRAY_AGG(t."ID" ORDER BY t."NAME") AS ids
                 , ARRAY_AGG(t."NAME" ORDER BY t."NAME") AS names
                 , ARRAY_AGG(t."UUID" ORDER BY t."NAME") AS uuids
              FROM "USERS_TEAMS" AS ut
             INNER JOIN "TEAM" AS t
                ON t."ID" = ut."TEAM_ID"
             WHERE ut."USER_ID" = usr."ID"
          ) AS teams ON TRUE
        """;

    private final DataSource dataSource;
    private final @Nullable String bearer;
    private @Nullable String tokenHash;
    private @Nullable Boolean portfolioAccessControlEnabled;

    public SessionTokenAuthenticationService(ContainerRequest request) {
        this(request, DataSourceRegistry.getInstance().getDefault());
    }

    SessionTokenAuthenticationService(ContainerRequest request, DataSource dataSource) {
        this.dataSource = dataSource;
        this.bearer = getAuthorizationToken(request);
    }

    @Override
    public boolean isSpecified() {
        return bearer != null;
    }

    @Override
    public @Nullable UserPrincipal authenticate() throws AuthenticationException {
        if (bearer == null) {
            return null;
        }

        final String hashedToken = SessionTokenService.sha256Hex(bearer);

        final LookupResult lookupResult = findUserBySessionTokenHash(hashedToken);
        if (lookupResult == null) {
            return null;
        }
        if (lookupResult.suspended()) {
            LOGGER.debug(
                    "Successfully authenticated user {}, but the account is suspended",
                    lookupResult.user().username());
            return null;
        }

        this.tokenHash = hashedToken;
        this.portfolioAccessControlEnabled = lookupResult.portfolioAccessControlEnabled();

        return lookupResult.user();
    }

    public @Nullable String getTokenHash() {
        return tokenHash;
    }

    public boolean isPortfolioAccessControlEnabled() {
        if (portfolioAccessControlEnabled == null) {
            throw new IllegalStateException("Authentication not attempted yet");
        }

        return portfolioAccessControlEnabled;
    }

    private static @Nullable String getAuthorizationToken(HttpHeaders headers) {
        final List<String> header = headers.getRequestHeader("Authorization");
        if (header != null && !header.isEmpty()) {
            final String bearer = header.getFirst();
            if (bearer.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return bearer.substring(7);
            }
        }

        return null;
    }

    private record LookupResult(UserPrincipal user, boolean suspended, boolean portfolioAccessControlEnabled) {

        private static final RowMapper ROW_MAPPER = new RowMapper();

        static final class RowMapper implements alpine.persistence.RowMapper<LookupResult> {

            private static final TeamRefsRowMapper TEAMS_ROW_MAPPER = new TeamRefsRowMapper();
            private static final PermissionsRowMapper PERMISSIONS_ROW_MAPPER = new PermissionsRowMapper();

            @Override
            public LookupResult map(ResultSet rs) throws SQLException {
                final String type = rs.getString("type");
                final UserType userType;
                try {
                    userType = UserType.valueOf(type);
                } catch (IllegalArgumentException e) {
                    throw new SQLException("Unknown user type: " + type, e);
                }

                final var principal = new UserPrincipal(
                        rs.getLong("id"),
                        rs.getString("username"),
                        userType,
                        TEAMS_ROW_MAPPER.map(rs),
                        PERMISSIONS_ROW_MAPPER.map(rs));

                return new LookupResult(principal, rs.getBoolean("suspended"), rs.getBoolean("acl_enabled"));
            }
        }
    }

    private @Nullable LookupResult findUserBySessionTokenHash(String tokenHash) {
        try (final Connection connection = dataSource.getConnection();
                final PreparedStatement ps = connection.prepareStatement(LOOKUP_QUERY)) {
            ps.setString(1, tokenHash);

            try (final ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }

                return LookupResult.ROW_MAPPER.map(rs);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to look up session", e);
        }
    }
}
