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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @since 5.0.0
 */
final class Crypto {

    private static final long ADVISORY_LOCK_ID = 5320496565362892580L;

    static {
        try {
            AeadConfig.register();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private final DataSource dataSource;
    private final Aead kek;

    Crypto(
            final DataSource dataSource,
            final DatabaseSecretManagerConfig config) {
        this.dataSource = dataSource;
        this.kek = loadKek(config);
    }

    String decrypt(final byte[] cipherText, final byte[] serializedDek) throws GeneralSecurityException {
        // Parse and decrypt the DEK with the KEK.
        final KeysetHandle dekKeysetHandle =
                TinkProtoKeysetFormat.parseEncryptedKeyset(
                        serializedDek, kek, new byte[0]);

        // Decrypt cipher text with the DEK.
        final Aead dek = dekKeysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        return new String(dek.decrypt(cipherText, new byte[0]), StandardCharsets.UTF_8);
    }

    record EncryptionResult(byte[] cipherText, byte[] serializedDek) {
    }

    EncryptionResult encrypt(final String plainText) throws GeneralSecurityException {
        // Generate a new DEK.
        final KeysetHandle dekHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
        final Aead dek = dekHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

        // Encrypt plain text with the new DEK.
        final byte[] cipherText = dek.encrypt(plainText.getBytes(StandardCharsets.UTF_8), new byte[0]);

        // Encrypt the DEK with the KEK and serialize it.
        final byte[] serializedDek =
                TinkProtoKeysetFormat.serializeEncryptedKeyset(
                        dekHandle, kek, new byte[0]);

        return new EncryptionResult(cipherText, serializedDek);
    }

    private Aead loadKek(DatabaseSecretManagerConfig config) {
        // The KEK is usually meant to be fetched from an external KMS.
        // We can't make KMSes a mandatory requirement, hence we support
        // fixed keys from config, or loading the KEK keyset from file instead.
        // However, support for external KMSes would be relatively easy to add if requested.
        // https://developers.google.com/tink/key-management-overview

        final Logger logger = LoggerFactory.getLogger(DatabaseSecretManager.class);

        final byte[] kekBytes = config.getKek();
        if (kekBytes != null) {
            logger.info("Loading KEK from config");

            // Derive a stable key ID from the key bytes.
            // Note that Tink by convention uses positive key IDs,
            // while hashCode can yield negative values.
            // Clear the sign bit to ensure we're always following the Tink convention.
            final int keyId = Arrays.hashCode(kekBytes) & 0x7FFFFFFF | 1;

            try {
                final var key = AesGcmKey.builder()
                        .setIdRequirement(keyId)
                        .setParameters(PredefinedAeadParameters.AES256_GCM)
                        .setKeyBytes(SecretBytes.copyFrom(kekBytes, InsecureSecretKeyAccess.get()))
                        .build();

                final var keysetHandle = KeysetHandle.newBuilder()
                        .addEntry(KeysetHandle
                                .importKey(key)
                                .withFixedId(keyId)
                                .makePrimary())
                        .build();

                return doLocked(connection -> {
                    verifyOrStoreKekKeyIds(connection, keysetHandle);
                    return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
                });
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Failed to load KEK from config", e);
            }
        }

        // NB: Throws when not configured.
        // Calling it here so we don't even open a DB connection if missing.
        final Path kekKeysetPath = config.getKekKeysetPath();

        return doLocked(connection -> {
            // This must execute in a locked context to avoid race conditions
            // when multiple instances start at the same time,
            // and the create-if-missing option is enabled.

            final KeysetHandle keysetHandle;
            if (Files.exists(kekKeysetPath)) {
                logger.info("Loading existing KEK keyset from {}", kekKeysetPath);
                keysetHandle =
                        TinkJsonProtoKeysetFormat.parseKeyset(
                                Files.readString(kekKeysetPath), InsecureSecretKeyAccess.get());
            } else if (config.isCreateKekKeysetIfMissing()) {
                logger.info("KEK keyset at {} does not exist yet; Creating it", kekKeysetPath);
                keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);

                // Ensure all directories leading up to the keyset exist.
                Files.createDirectories(kekKeysetPath.getParent());

                // Create the file with as restrictive permissions as possible.
                // Note that GROUP_READ is necessary for OpenShift deployments,
                // since the user ID is assigned randomly.
                final FileAttribute<?> posixPermissionsAttribute =
                        PosixFilePermissions.asFileAttribute(Set.of(
                                PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE,
                                PosixFilePermission.GROUP_READ));

                if (!System.getProperty("os.name").toLowerCase().startsWith("win")) {
                    Files.createFile(kekKeysetPath, posixPermissionsAttribute);
                } else {
                    // POSIX permissions don't work on Windows.
                    // Note that this fallback is mainly for developers working on Windows
                    // machines, since our official distribution is a Linux-based container image.
                    Files.createFile(kekKeysetPath);
                }

                Files.writeString(
                        kekKeysetPath,
                        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get()),
                        StandardOpenOption.WRITE);
            } else {
                throw new IllegalStateException("""
                        KEK keyset at %s does not exist and \
                        dt.secret-management.database.kek-keyset.create-if-missing \
                        is false. Can not continue without a valid KEK keyset.\
                        """.formatted(kekKeysetPath));
            }

            verifyOrStoreKekKeyIds(connection, keysetHandle);

            return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        });
    }

    static Set<Integer> extractKeyIds(final KeysetHandle keysetHandle) {
        return IntStream.range(0, keysetHandle.size())
                .mapToObj(i -> keysetHandle.getAt(i).getId())
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static String serializeKeyIds(Set<Integer> keyIds) {
        return keyIds.stream()
                .map(String::valueOf)
                .collect(Collectors.joining(","));
    }

    private static Set<Integer> deserializeKeyIds(String value) {
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(Integer::parseInt)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static void verifyOrStoreKekKeyIds(Connection connection, KeysetHandle keysetHandle) throws SQLException {
        // Prevent the scenario where multiple nodes generate different KEK keysets,
        // which could lead to secret decryption failures at runtime.

        final Set<Integer> loadedKeyIds = extractKeyIds(keysetHandle);

        final String existingValue;
        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT "PROPERTYVALUE"
                  FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = 'secret-management'
                   AND "PROPERTYNAME" = 'kek-keyset-key-ids'
                """)) {
            final ResultSet rs = ps.executeQuery();
            existingValue = rs.next()
                    ? rs.getString(1)
                    : null;
        }

        if (existingValue == null) {
            upsertKeyIds(connection, serializeKeyIds(loadedKeyIds));
            return;
        }

        final Set<Integer> storedKeyIds = deserializeKeyIds(existingValue);
        if (loadedKeyIds.equals(storedKeyIds)) {
            return;
        }

        // Rotation: the loaded keyset contains all previously known keys AND new ones.
        if (loadedKeyIds.containsAll(storedKeyIds)) {
            LoggerFactory
                    .getLogger(DatabaseSecretManager.class)
                    .info("KEK keyset has been rotated; Updating stored key IDs");
            upsertKeyIds(connection, serializeKeyIds(loadedKeyIds));
            return;
        }

        throw new IllegalStateException("""
                KEK keyset mismatch. The loaded keyset does not contain all keys previously \
                registered in the database (expected at least %s, got %s). This typically indicates \
                that multiple nodes are using different KEK keysets, which leads to silent data \
                corruption. Ensure all nodes share the same KEK keyset file (e.g. via a Kubernetes \
                secret mount, or shared volume).""".formatted(serializeKeyIds(storedKeyIds), serializeKeyIds(loadedKeyIds)));
    }

    private static void upsertKeyIds(Connection connection, String keyIdsValue) throws SQLException {
        try (final PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO "CONFIGPROPERTY" ("GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
                VALUES ('secret-management', 'kek-keyset-key-ids', 'STRING', ?)
                ON CONFLICT ("GROUPNAME", "PROPERTYNAME")
                DO UPDATE SET "PROPERTYVALUE" = ?
                """)) {
            ps.setString(1, keyIdsValue);
            ps.setString(2, keyIdsValue);
            ps.executeUpdate();
        }
    }

    private <T> T doLocked(CheckedFunction<Connection, T> function) {
        try (final Connection connection = dataSource.getConnection()) {
            final boolean originalAutoCommit = connection.getAutoCommit();
            try {
                connection.setAutoCommit(false);

                try (final PreparedStatement ps = connection.prepareStatement("""
                        
                           SELECT pg_advisory_xact_lock(?)
                        """)) {
                    ps.setLong(1, ADVISORY_LOCK_ID);
                    ps.execute();
                } catch (SQLException e) {
                    throw new IllegalStateException("Failed to acquire advisory lock", e);
                }

                final T result = function.apply(connection);
                connection.commit();
                return result;
            } catch (Exception e) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackEx) {
                    e.addSuppressed(rollbackEx);
                }

                if (e instanceof final RuntimeException re) {
                    throw re;
                }

                throw new IllegalStateException(e);
            } finally {
                try {
                    connection.setAutoCommit(originalAutoCommit);
                } catch (SQLException ignored) {
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to execute locked operation", e);
        }
    }

    @FunctionalInterface
    private interface CheckedFunction<T, R> {
        R apply(T t) throws Exception;
    }

}
