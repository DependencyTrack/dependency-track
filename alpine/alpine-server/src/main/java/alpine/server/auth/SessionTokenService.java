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

import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.NullMarked;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * @since 5.0.0
 */
@NullMarked
public final class SessionTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_BYTES = 32;

    private final Duration sessionTimeout;
    private final DataSource dataSource;

    public SessionTokenService() {
        this(ConfigProvider.getConfig());
    }

    SessionTokenService(Config config) {
        this.sessionTimeout = Duration.ofMillis(config.getOptionalValue("dt.auth.session-timeout-ms", long.class)
                .orElse(Duration.ofHours(8).toMillis()));
        this.dataSource = DataSourceRegistry.getInstance().getDefault();
    }

    public String createSession(long userId) {
        try (final Connection connection = dataSource.getConnection()) {
            return createSession(connection, userId, sessionTimeout);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to create session", e);
        }
    }

    public String createSession(Connection connection, long userId, Duration lifetime) {
        final byte[] tokenBytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(tokenBytes);
        final String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        final var now = Instant.now();
        try (final PreparedStatement ps = connection.prepareStatement("""
            INSERT INTO "USER_SESSION" ("TOKEN_HASH", "USER_ID", "CREATED_AT", "EXPIRES_AT")
            VALUES (?, ?, ?, ?)
            """)) {
            ps.setString(1, sha256Hex(rawToken));
            ps.setLong(2, userId);
            ps.setTimestamp(3, Timestamp.from(now));
            ps.setTimestamp(4, Timestamp.from(now.plus(lifetime)));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to create session", e);
        }

        return rawToken;
    }

    public boolean deleteSession(String rawToken, long userId) {
        try (final Connection connection = dataSource.getConnection();
                final PreparedStatement ps = connection.prepareStatement("""
                    DELETE
                      FROM "USER_SESSION"
                     WHERE "TOKEN_HASH" = ?
                       AND "USER_ID" = ?
                    """)) {
            ps.setString(1, sha256Hex(rawToken));
            ps.setLong(2, userId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to revoke session", e);
        }
    }

    public int deleteExpiredSessions() {
        try (final Connection connection = dataSource.getConnection();
                final PreparedStatement ps = connection.prepareStatement("""
                    DELETE
                      FROM "USER_SESSION"
                     WHERE "EXPIRES_AT" < NOW()
                    """)) {
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to delete expired sessions", e);
        }
    }

    static String sha256Hex(String input) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
