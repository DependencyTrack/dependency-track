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
package alpine.server.auth;

import alpine.model.ApiKey;
import alpine.model.auth.ApiKeyPrincipal;
import alpine.security.ApiKeyDecoder;
import alpine.security.InvalidApiKeyFormatException;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.glassfish.jersey.server.ContainerRequest;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Authentication service that validates API keys.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@NullMarked
public final class ApiKeyAuthenticationService implements AuthenticationService<ApiKeyPrincipal> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyAuthenticationService.class);
    private static final String LOOKUP_QUERY = /* language=SQL */ """
        WITH api_key AS (
          SELECT "ID"
               , "PUBLIC_ID"
               , "SECRET_HASH"
            FROM "APIKEY"
           WHERE "PUBLIC_ID" = ?
        )
        SELECT api_key."ID" AS id
             , api_key."PUBLIC_ID" AS public_id
             , api_key."SECRET_HASH" AS secret_hash
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
                   FROM "APIKEYS_TEAMS" AS akt
                  INNER JOIN "TEAMS_PERMISSIONS" AS tp
                     ON tp."TEAM_ID" = akt."TEAM_ID"
                  INNER JOIN "PERMISSION" AS p
                     ON p."ID" = tp."PERMISSION_ID"
                  WHERE akt."APIKEY_ID" = api_key."ID"
               ) AS permissions
          FROM api_key
          LEFT JOIN LATERAL (
            SELECT ARRAY_AGG(t."ID" ORDER BY t."NAME") AS ids
                 , ARRAY_AGG(t."NAME" ORDER BY t."NAME") AS names
                 , ARRAY_AGG(t."UUID" ORDER BY t."NAME") AS uuids
              FROM "APIKEYS_TEAMS" AS akt
             INNER JOIN "TEAM" AS t
                ON t."ID" = akt."TEAM_ID"
             WHERE akt."APIKEY_ID" = api_key."ID"
          ) AS teams ON TRUE
        """;

    private final DataSource dataSource;
    private final @Nullable String assertedApiKey;
    private @Nullable Boolean portfolioAccessControlEnabled;

    /**
     * Given the specified ContainerRequest, the constructor retrieves a header
     * named 'X-Api-Key', if it exists.
     * @param request the ContainerRequest object
     * @since 1.0.0
     */
    public ApiKeyAuthenticationService(ContainerRequest request) {
        this(request, DataSourceRegistry.getInstance().getDefault());
    }

    ApiKeyAuthenticationService(ContainerRequest request, DataSource dataSource) {
        this.dataSource = dataSource;
        this.assertedApiKey = request.getHeaderString("X-Api-Key");
    }

    public boolean isPortfolioAccessControlEnabled() {
        if (portfolioAccessControlEnabled == null) {
            throw new IllegalStateException("Authentication not attempted yet");
        }

        return portfolioAccessControlEnabled;
    }

    /**
     * Returns whether an API key was specified or not.
     * @return true if API key was specified, false if not
     * @since 1.0.0
     */
    public boolean isSpecified() {
        return assertedApiKey != null;
    }

    /**
     * Authenticates the API key (if it was specified in the X-Api-Key header)
     * and returns a Principal if authentication is successful.
     * Otherwise, throws an AuthenticationException.
     * @return the authenticated {@link ApiKeyPrincipal}
     * @throws AuthenticationException upon an authentication failure
     * @since 1.0.0
     */
    public ApiKeyPrincipal authenticate() throws AuthenticationException {
        final ApiKey decodedApiKey;
        try {
            decodedApiKey = ApiKeyDecoder.decode(assertedApiKey);
        } catch (InvalidApiKeyFormatException e) {
            LOGGER.debug("Format of the provided API key is invalid", e);
            throw new AuthenticationException();
        }

        final LookupResult lookupResult = findApiKeyByPublicId(decodedApiKey.getPublicId());
        if (lookupResult == null) {
            LOGGER.debug("No API key found for public ID {}", decodedApiKey.getPublicId());
            throw new AuthenticationException();
        }

        final byte[] assertedSecretHash = decodedApiKey.getSecretHash().getBytes(StandardCharsets.UTF_8);
        final byte[] storedSecretHash = lookupResult.secretHash().getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(assertedSecretHash, storedSecretHash)) {
            LOGGER.debug("API key secret hashes do not match");
            throw new AuthenticationException();
        }

        this.portfolioAccessControlEnabled = lookupResult.portfolioAccessControlEnabled();

        return lookupResult.principal();
    }

    private record LookupResult(ApiKeyPrincipal principal, String secretHash, boolean portfolioAccessControlEnabled) {

        private static final RowMapper ROW_MAPPER = new RowMapper();

        static final class RowMapper implements alpine.persistence.RowMapper<LookupResult> {

            private static final TeamRefsRowMapper TEAMS_ROW_MAPPER = new TeamRefsRowMapper();
            private static final PermissionsRowMapper PERMISSIONS_ROW_MAPPER = new PermissionsRowMapper();

            @Override
            public LookupResult map(ResultSet rs) throws SQLException {
                final var principal = new ApiKeyPrincipal(
                        rs.getLong("id"),
                        rs.getString("public_id"),
                        TEAMS_ROW_MAPPER.map(rs),
                        PERMISSIONS_ROW_MAPPER.map(rs));

                return new LookupResult(principal, rs.getString("secret_hash"), rs.getBoolean("acl_enabled"));
            }
        }
    }

    private @Nullable LookupResult findApiKeyByPublicId(String publicId) {
        try (final Connection connection = dataSource.getConnection();
                final PreparedStatement ps = connection.prepareStatement(LOOKUP_QUERY)) {
            ps.setString(1, publicId);

            try (final ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }

                return LookupResult.ROW_MAPPER.map(rs);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to look up API key " + publicId, e);
        }
    }
}
