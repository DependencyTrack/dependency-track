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
package org.dependencytrack.secret.management.database;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretAlreadyExistsException;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.secret.management.SecretManager.requireValidName;

/**
 * A {@link SecretManager} that stores secrets in the database.
 *
 * @since 5.0.0
 */
final class DatabaseSecretManager implements SecretManager {

    static final String NAME = "database";

    private final DataSource dataSource;
    private final Crypto crypto;
    private final PageTokenEncoder pageTokenEncoder;

    DatabaseSecretManager(
            DataSource dataSource,
            Crypto crypto,
            PageTokenEncoder pageTokenEncoder) {
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
        this.crypto = requireNonNull(crypto, "crypto must not be null");
        this.pageTokenEncoder = requireNonNull(pageTokenEncoder, "pageTokenEncoder must not be null");
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public void createSecret(
            String name,
            @Nullable String description,
            String value) {
        requireValidName(name);
        requireNonNull(value, "value must not be null");

        final Crypto.EncryptionResult encryptionResult;
        try {
            encryptionResult = crypto.encrypt(value);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt secret value", e);
        }

        final int rowsModified;
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     INSERT INTO "SECRET" ("NAME", "DESCRIPTION", "VALUE", "DEK", "CREATED_AT")
                     VALUES (?, ?, ?, ?, NOW())
                     ON CONFLICT ("NAME") DO NOTHING
                     """)) {
            ps.setString(1, name);
            ps.setString(2, description);
            ps.setBytes(3, encryptionResult.cipherText());
            ps.setBytes(4, encryptionResult.serializedDek());
            rowsModified = ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to create secret record", e);
        }

        if (rowsModified == 0) {
            throw new SecretAlreadyExistsException(name);
        }
    }

    @Override
    public boolean updateSecret(
            String name,
            @Nullable String description,
            @Nullable String value) {
        requireValidName(name);

        if (description == null && value == null) {
            return false;
        }

        final Crypto.EncryptionResult encryptionResult;
        if (value != null) {
            try {
                encryptionResult = crypto.encrypt(value);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Failed to encrypt secret value", e);
            }
        } else {
            encryptionResult = null;
        }

        final boolean exists;
        final boolean updated;
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     WITH
                     existing AS (
                       SELECT "NAME", "DESCRIPTION", "VALUE"
                         FROM "SECRET"
                        WHERE "NAME" = ?
                          FOR UPDATE
                     ),
                     updated AS (
                       UPDATE "SECRET"
                          SET "DESCRIPTION" = COALESCE(?, "DESCRIPTION")
                            , "VALUE" = COALESCE(?, "VALUE")
                            , "DEK" =  COALESCE(?, "DEK")
                            , "UPDATED_AT" = NOW()
                        WHERE "NAME" = ?
                          AND (
                                (? IS NOT NULL AND "DESCRIPTION" IS DISTINCT FROM ?)
                                OR (? IS NOT NULL AND "VALUE" IS DISTINCT FROM ?)
                              )
                       RETURNING 1
                     )
                     SELECT EXISTS(SELECT 1 FROM existing) AS exists
                          , (SELECT COUNT(*) FROM updated) AS updated
                     """)) {
            ps.setString(1, name);
            ps.setString(2, description);
            ps.setBytes(3, encryptionResult != null ? encryptionResult.cipherText() : null);
            ps.setBytes(4, encryptionResult != null ? encryptionResult.serializedDek() : null);
            ps.setString(5, name);
            ps.setString(6, description);
            ps.setString(7, description);
            ps.setBytes(8, encryptionResult != null ? encryptionResult.cipherText() : null);
            ps.setBytes(9, encryptionResult != null ? encryptionResult.cipherText() : null);

            final ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                throw new IllegalStateException("Query did not return any results");
            }
            exists = rs.getBoolean(1);
            updated = rs.getInt(2) > 0;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to update secret record", e);
        }

        if (!exists) {
            throw new NoSuchElementException("No secret with name %s found".formatted(name));
        }

        return updated;
    }

    @Override
    public void deleteSecret(String name) {
        requireValidName(name);

        final int rowsModified;
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     DELETE
                       FROM "SECRET"
                      WHERE "NAME" = ?
                     """)) {
            ps.setString(1, name);
            rowsModified = ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to delete secret record", e);
        }

        if (rowsModified == 0) {
            throw new NoSuchElementException("No secret with name %s found".formatted(name));
        }
    }

    @Override
    public @Nullable SecretMetadata getSecretMetadata(String name) {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT "NAME"
                          , "DESCRIPTION"
                          , "CREATED_AT"
                          , "UPDATED_AT"
                       FROM "SECRET"
                      WHERE "NAME" = ?
                     """)) {
            ps.setString(1, name);

            final ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            return new SecretMetadata(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getTimestamp(3) != null
                            ? Instant.ofEpochMilli(rs.getTimestamp(3).getTime())
                            : null,
                    rs.getTimestamp(4) != null
                            ? Instant.ofEpochMilli(rs.getTimestamp(4).getTime())
                            : null);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query secret metadata", e);
        }
    }

    @Override
    public @Nullable String getSecretValue(String name) {
        requireValidName(name);

        final byte[] cipherText;
        final byte[] serializedDek;

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT "VALUE"
                          , "DEK"
                       FROM "SECRET"
                      WHERE "NAME" = ?
                     """)) {
            ps.setString(1, name);

            final ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            cipherText = rs.getBytes(1);
            serializedDek = rs.getBytes(2);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query secret value", e);
        }

        try {
            return crypto.decrypt(cipherText, serializedDek);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt secret value", e);
        }
    }

    record ListSecretsPageToken(String lastName) implements PageToken {
    }

    @Override
    public Page<SecretMetadata> listSecretMetadata(ListSecretsRequest request) {
        final var decodedPageToken = pageTokenEncoder.decode(request.pageToken(), ListSecretsPageToken.class);

        final long totalCount;
        final var secrets = new ArrayList<SecretMetadata>();

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement countQuery = connection.prepareStatement("""
                     SELECT COUNT(*)
                       FROM "SECRET"
                      WHERE (? IS NULL OR LOWER("NAME") LIKE (LOWER(?) || '%'))
                     """);
             final PreparedStatement listQuery = connection.prepareStatement("""
                     SELECT "NAME"
                          , "DESCRIPTION"
                          , "CREATED_AT"
                          , "UPDATED_AT"
                       FROM "SECRET"
                      WHERE (? IS NULL OR LOWER("NAME") LIKE (LOWER(?) || '%'))
                        AND (? IS NULL OR "NAME" > ?)
                      ORDER BY "NAME"
                      LIMIT ? + 1
                     """)) {
            countQuery.setString(1, request.searchText());
            countQuery.setString(2, request.searchText());
            final ResultSet countRs = countQuery.executeQuery();
            countRs.next();
            totalCount = countRs.getLong(1);

            listQuery.setString(1, request.searchText());
            listQuery.setString(2, request.searchText());
            listQuery.setString(3, decodedPageToken != null ? decodedPageToken.lastName() : null);
            listQuery.setString(4, decodedPageToken != null ? decodedPageToken.lastName() : null);
            listQuery.setInt(5, request.limit());

            final ResultSet rs = listQuery.executeQuery();
            while (rs.next()) {
                secrets.add(
                        new SecretMetadata(
                                rs.getString(1),
                                rs.getString(2),
                                rs.getTimestamp(3) != null
                                        ? Instant.ofEpochMilli(rs.getTimestamp(3).getTime())
                                        : null,
                                rs.getTimestamp(4) != null
                                        ? Instant.ofEpochMilli(rs.getTimestamp(4).getTime())
                                        : null));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query secret metadata", e);
        }

        final var resultItems = secrets.size() > request.limit()
                ? secrets.subList(0, request.limit())
                : secrets;

        final String nextPageToken = secrets.size() > request.limit()
                ? pageTokenEncoder.encode(new ListSecretsPageToken(resultItems.getLast().name()))
                : null;

        return new Page<>(resultItems, nextPageToken)
                .withTotalCount(totalCount, Page.TotalCount.Type.EXACT);
    }

    @Override
    public void close() {
        if (dataSource instanceof final Closeable closeable) {
            try {
                closeable.close();
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to close data source", e);
            }
        }
    }

}
