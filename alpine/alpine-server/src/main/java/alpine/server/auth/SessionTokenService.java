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

import alpine.persistence.AlpineQueryManager;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.NullMarked;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

/**
 * @since 5.0.0
 */
@NullMarked
public final class SessionTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_BYTES = 32;

    private final long sessionTimeoutMillis;

    public SessionTokenService() {
        this(ConfigProvider.getConfig());
    }

    SessionTokenService(Config config) {
        this.sessionTimeoutMillis = config
                .getOptionalValue("dt.auth.session-timeout-ms", long.class)
                .orElse(TimeUnit.HOURS.toMillis(8));
    }

    public String createSession(long userId) {
        final byte[] tokenBytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(tokenBytes);
        final String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        final String tokenHash = sha256Hex(rawToken);

        final var now = Instant.now();
        final Instant expiresAt = now.plusMillis(sessionTimeoutMillis);
        try (final var qm = new AlpineQueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            final JDOConnection jdoConnection = pm.getDataStoreConnection();
            final var connection = (Connection) jdoConnection.getNativeConnection();

            try (final PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO "USER_SESSION" ("TOKEN_HASH", "USER_ID", "CREATED_AT", "EXPIRES_AT")
                    VALUES (?, ?, ?, ?)
                    """)) {
                ps.setString(1, tokenHash);
                ps.setLong(2, userId);
                ps.setTimestamp(3, Timestamp.from(now));
                ps.setTimestamp(4, Timestamp.from(expiresAt));
                ps.executeUpdate();
            } finally {
                jdoConnection.close();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to create session", e);
        }

        return rawToken;
    }

    public boolean deleteSession(String rawToken, long userId) {
        final String tokenHash = sha256Hex(rawToken);

        try (var qm = new AlpineQueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            final JDOConnection jdoConnection = pm.getDataStoreConnection();
            final var connection = (Connection) jdoConnection.getNativeConnection();

            try (var ps = connection.prepareStatement("""
                    DELETE
                      FROM "USER_SESSION"
                     WHERE "TOKEN_HASH" = ?
                       AND "USER_ID" = ?
                    """)) {
                ps.setString(1, tokenHash);
                ps.setLong(2, userId);
                return ps.executeUpdate() > 0;
            } finally {
                jdoConnection.close();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to revoke session", e);
        }
    }

    public int deleteExpiredSessions() {
        try (var qm = new AlpineQueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            final JDOConnection jdoConnection = pm.getDataStoreConnection();
            final var connection = (Connection) jdoConnection.getNativeConnection();

            try (final PreparedStatement ps = connection.prepareStatement("""
                    DELETE
                      FROM "USER_SESSION"
                     WHERE "EXPIRES_AT" < NOW()
                    """)) {
                return ps.executeUpdate();
            } finally {
                jdoConnection.close();
            }
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
