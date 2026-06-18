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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.testing.database.TestDatabaseExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import org.postgresql.ds.PGSimpleDataSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class CryptoTest {

    @RegisterExtension
    static final TestDatabaseExtension database = new TestDatabaseExtension();

    @TempDir
    private Path tempDir;

    private static PGSimpleDataSource dataSource;

    @BeforeAll
    static void beforeAll() throws Exception {
        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(database.jdbcUrl());
        dataSource.setUser(database.username());
        dataSource.setPassword(database.password());
    }

    @Test
    void shouldStoreAndAcceptSameKeyset() {
        final Path kekPath = tempDir.resolve("kek.json");

        final DatabaseSecretManagerConfig config = createConfig(kekPath, true);
        new Crypto(dataSource, config);

        // Second instance with the same keyset file should succeed.
        final DatabaseSecretManagerConfig config2 = createConfig(kekPath, false);
        assertThatNoException().isThrownBy(() -> new Crypto(dataSource, config2));
    }

    @Test
    void shouldRejectDifferentKeyset() throws Exception {
        final Path kekPathA = tempDir.resolve("kek-a.json");
        final DatabaseSecretManagerConfig configA = createConfig(kekPathA, true);
        new Crypto(dataSource, configA);

        // Create a second, completely independent keyset.
        final Path kekPathB = tempDir.resolve("kek-b.json");
        final KeysetHandle differentKeyset = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
        Files.writeString(kekPathB,
                TinkJsonProtoKeysetFormat.serializeKeyset(differentKeyset, InsecureSecretKeyAccess.get()));

        final DatabaseSecretManagerConfig configB = createConfig(kekPathB, false);
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> new Crypto(dataSource, configB))
                .withMessageContaining("KEK keyset mismatch");
    }

    @Test
    void shouldAcceptRotatedKeyset() throws Exception {
        final Path kekPath = tempDir.resolve("kek.json");
        final DatabaseSecretManagerConfig config = createConfig(kekPath, true);
        new Crypto(dataSource, config);

        // Rotate: add a new key and make it primary.
        final KeysetHandle originalKeyset =
                TinkJsonProtoKeysetFormat.parseKeyset(
                        Files.readString(kekPath), InsecureSecretKeyAccess.get());
        final var keysetManager = KeysetManager.withKeysetHandle(originalKeyset);
        keysetManager.addNewKey(AeadKeyTemplates.AES128_GCM, true);

        final Path rotatedPath = tempDir.resolve("kek-rotated.json");
        Files.writeString(rotatedPath,
                TinkJsonProtoKeysetFormat.serializeKeyset(
                        keysetManager.getKeysetHandle(), InsecureSecretKeyAccess.get()));

        final DatabaseSecretManagerConfig configB = createConfig(rotatedPath, false);
        assertThatNoException().isThrownBy(() -> new Crypto(dataSource, configB));
    }

    @Test
    void shouldAcceptNewKeysetAfterKeyIdReset() throws Exception {
        final Path kekPathA = tempDir.resolve("kek-a.json");
        final DatabaseSecretManagerConfig configA = createConfig(kekPathA, true);
        new Crypto(dataSource, configA);

        // Delete stored key IDs to simulate intentional keyset replacement.
        try (final Connection connection = dataSource.getConnection();
             final Statement statement = connection.createStatement()) {
            statement.execute("""
                    DELETE FROM "CONFIGPROPERTY"
                     WHERE "GROUPNAME" = 'secret-management'
                       AND "PROPERTYNAME" = 'kek-keyset-key-ids'
                    """);
        }

        // A completely different keyset should now be accepted.
        final Path kekPathB = tempDir.resolve("kek-b.json");
        final KeysetHandle differentKeyset = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
        Files.writeString(kekPathB, TinkJsonProtoKeysetFormat.serializeKeyset(differentKeyset, InsecureSecretKeyAccess.get()));

        final DatabaseSecretManagerConfig configB = createConfig(kekPathB, false);
        assertThatNoException().isThrownBy(() -> new Crypto(dataSource, configB));
    }

    @Test
    void shouldEncryptAndDecryptWithConfigKek() throws Exception {
        final byte[] kekBytes = new byte[32];
        new SecureRandom().nextBytes(kekBytes);

        final DatabaseSecretManagerConfig config = createConfigWithKek(kekBytes);
        final var crypto = new Crypto(dataSource, config);

        final Crypto.EncryptionResult result = crypto.encrypt("secret-value");
        assertThat(crypto.decrypt(result.cipherText(), result.serializedDek())).isEqualTo("secret-value");
    }

    @Test
    void shouldRejectDifferentConfigKek() {
        final byte[] kekBytesA = new byte[32];
        new SecureRandom().nextBytes(kekBytesA);
        new Crypto(dataSource, createConfigWithKek(kekBytesA));

        final byte[] kekBytesB = new byte[32];
        new SecureRandom().nextBytes(kekBytesB);
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> new Crypto(dataSource, createConfigWithKek(kekBytesB)))
                .withMessageContaining("KEK keyset mismatch");
    }

    @Test
    void shouldAcceptSameConfigKek() {
        final byte[] kekBytes = new byte[32];
        new SecureRandom().nextBytes(kekBytes);

        new Crypto(dataSource, createConfigWithKek(kekBytes));
        assertThatNoException().isThrownBy(() -> new Crypto(dataSource, createConfigWithKek(kekBytes)));
    }

    private DatabaseSecretManagerConfig createConfigWithKek(byte[] kekBytes) {
        final String encodedKek = Base64.getEncoder().encodeToString(kekBytes);
        return new DatabaseSecretManagerConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(Map.ofEntries(
                                Map.entry("dt.datasource.secrets.url", database.jdbcUrl()),
                                Map.entry("dt.datasource.secrets.username", database.username()),
                                Map.entry("dt.datasource.secrets.password", database.password()),
                                Map.entry("dt.secret-management.database.datasource.name", "secrets"),
                                Map.entry("dt.secret-management.database.kek", encodedKek)))
                        .build());
    }

    private DatabaseSecretManagerConfig createConfig(Path kekPath, boolean createIfMissing) {
        return new DatabaseSecretManagerConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(Map.ofEntries(
                                Map.entry("dt.datasource.secrets.url", database.jdbcUrl()),
                                Map.entry("dt.datasource.secrets.username", database.username()),
                                Map.entry("dt.datasource.secrets.password", database.password()),
                                Map.entry("dt.secret-management.database.datasource.name", "secrets"),
                                Map.entry("dt.secret-management.database.kek-keyset.path", kekPath.toString()),
                                Map.entry("dt.secret-management.database.kek-keyset.create-if-missing",
                                        String.valueOf(createIfMissing))))
                        .build());
    }

}
