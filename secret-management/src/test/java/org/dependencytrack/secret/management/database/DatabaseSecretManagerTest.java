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
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.migration.MigrationExecutor;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretAlreadyExistsException;
import org.dependencytrack.secret.management.SecretManager;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

@Testcontainers
class DatabaseSecretManagerTest {

    @Container
    private static final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"));

    @TempDir
    private static Path tempDir;
    private static Path kekKeysetPath;

    private static DataSourceRegistry dataSourceRegistry;
    private static SecretManager secretManager;

    @BeforeAll
    static void beforeAll() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        new MigrationExecutor(dataSource).execute();

        kekKeysetPath = tempDir.resolve("kek-keyset.json");

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.secrets.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.secrets.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.secrets.password", postgresContainer.getPassword()),
                        Map.entry("dt.secret-management.database.datasource.name", "secrets"),
                        Map.entry("dt.secret-management.database.kek-keyset.path", kekKeysetPath.toString()),
                        Map.entry("dt.secret-management.database.kek-keyset.create-if-missing", "true")))
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        secretManager = new DatabaseSecretManagerProvider(dataSourceRegistry)
                .create(config, new SimplePageTokenEncoder());
    }

    @AfterEach
    void afterEach() throws Exception {
        try (final Connection connection = postgresContainer.createConnection("");
             final Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE \"SECRET\"");
        }
    }

    @AfterAll
    static void afterAll() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Test
    void nameShouldBeDatabase() {
        assertThat(secretManager.name()).isEqualTo("database");
    }

    @Test
    void isReadOnlyShouldReturnFalse() {
        assertThat(secretManager.isReadOnly()).isFalse();
    }

    @Nested
    class CreateSecretTest {

        @Test
        void shouldCreateSecret() throws Exception {
            secretManager.createSecret("name", "description", "secret");

            assertThat(getAllSecrets()).satisfiesExactly(record -> {
                assertThat(record.name()).isEqualTo("name");
                assertThat(record.description()).isEqualTo("description");
                assertThat(record.value()).isNotEqualTo("secret");
                assertThat(record.createdAt()).isNotNull();
                assertThat(record.updatedAt()).isNull();
            });
        }

        @Test
        void shouldThrowWhenNameIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> secretManager.createSecret(null, "description", "secret"))
                    .withMessage("name must not be null");
        }

        @Test
        void shouldNotThrowWhenDescriptionIsNull() {
            assertThatNoException()
                    .isThrownBy(() -> secretManager.createSecret("name", null, "secret"));
        }

        @Test
        void shouldThrowWhenValueIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> secretManager.createSecret("name", "description", null))
                    .withMessage("value must not be null");
        }

        @Test
        void shouldThrowWhenAlreadyExists() {
            secretManager.createSecret("name", "description", "secret");

            assertThatExceptionOfType(SecretAlreadyExistsException.class)
                    .isThrownBy(() -> secretManager.createSecret("name", "description", "secret"));
        }

    }

    @Nested
    class UpdateSecretTest {

        @Test
        void shouldReturnTrueWhenSecretWasUpdated() throws Exception {
            secretManager.createSecret("name", "description", "secret");

            final boolean updated = secretManager.updateSecret("name", "newDescription", "newSecret");
            assertThat(updated).isTrue();

            assertThat(getAllSecrets()).satisfiesExactly(record -> {
                assertThat(record.name()).isEqualTo("name");
                assertThat(record.description()).isEqualTo("newDescription");
                assertThat(record.value()).isNotNull();
                assertThat(record.createdAt()).isNotNull();
                assertThat(record.updatedAt()).isNotNull();
            });
        }

        @Test
        void shouldReturnFalseWhenSecretWasNotUpdated() throws Exception {
            secretManager.createSecret("name", "description", "secret");

            // NB: The secret manager can't detect whether the value is unchanged
            // because it is stored encrypted, and two encryptions do not result in
            // the same exact value.
            final boolean updated = secretManager.updateSecret("name", "description", null);
            assertThat(updated).isFalse();

            assertThat(getAllSecrets()).satisfiesExactly(record -> {
                assertThat(record.name()).isEqualTo("name");
                assertThat(record.description()).isEqualTo("description");
                assertThat(record.value()).isNotNull();
                assertThat(record.createdAt()).isNotNull();
                assertThat(record.updatedAt()).isNull();
            });
        }

        @Test
        void shouldThrowWhenNameIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> secretManager.updateSecret(null, "description", "secret"))
                    .withMessage("name must not be null");
        }

        @Test
        void shouldThrowWhenSecretDoesNotExist() {
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> secretManager.updateSecret("name", "description", "secret"));
        }

    }

    @Nested
    class DeleteSecretTest {

        @Test
        void shouldDeleteSecret() throws Exception {
            secretManager.createSecret("name", "description", "secret");
            assertThat(getAllSecrets()).hasSize(1);

            secretManager.deleteSecret("name");
            assertThat(getAllSecrets()).isEmpty();
        }

        @Test
        void shouldThrowWhenSecretWasNotDeleted() {
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> secretManager.deleteSecret("name"));
        }

    }

    @Nested
    class GetSecretValueTest {

        @Test
        void shouldReturnSecretValueIfExists() {
            secretManager.createSecret("name", "description", "secret");
            assertThat(secretManager.getSecretValue("name")).isEqualTo("secret");
        }

        @Test
        void shouldReturnNullIfNotExists() {
            assertThat(secretManager.getSecretValue("name")).isNull();
        }

    }

    @Nested
    class GetSecretMetadataTest {

        @Test
        void shouldReturnMetadataIfExists() {
            secretManager.createSecret("name", "description", "secret");

            final var metadata = secretManager.getSecretMetadata("name");
            assertThat(metadata).isNotNull();
            assertThat(metadata.name()).isEqualTo("name");
            assertThat(metadata.description()).isEqualTo("description");
            assertThat(metadata.createdAt()).isNotNull();
            assertThat(metadata.updatedAt()).isNull();
        }

        @Test
        void shouldReturnMetadataWithUpdatedAtIfSecretWasUpdated() {
            secretManager.createSecret("name", "description", "secret");
            secretManager.updateSecret("name", "newDescription", null);

            final var metadata = secretManager.getSecretMetadata("name");
            assertThat(metadata).isNotNull();
            assertThat(metadata.name()).isEqualTo("name");
            assertThat(metadata.description()).isEqualTo("newDescription");
            assertThat(metadata.createdAt()).isNotNull();
            assertThat(metadata.updatedAt()).isNotNull();
        }

        @Test
        void shouldReturnNullIfNotExists() {
            assertThat(secretManager.getSecretMetadata("doesNotExist")).isNull();
        }

    }

    @Nested
    class ListSecretsTest {

        @Test
        void shouldListSecrets() {
            secretManager.createSecret("foo", "description", "secret");
            secretManager.createSecret("bar", null, "secret");

            final var page = secretManager.listSecretMetadata(new ListSecretsRequest(null, null, 100));
            assertThat(page.totalCount()).isNotNull();
            assertThat(page.totalCount().value()).isEqualTo(2);
            assertThat(page.totalCount().type()).isEqualTo(Page.TotalCount.Type.EXACT);
            assertThat(page.items())
                    .satisfiesExactlyInAnyOrder(
                            record -> {
                                assertThat(record.name()).isEqualTo("foo");
                                assertThat(record.description()).isEqualTo("description");
                                assertThat(record.createdAt()).isNotNull();
                                assertThat(record.updatedAt()).isNull();
                            },
                            record -> {
                                assertThat(record.name()).isEqualTo("bar");
                                assertThat(record.description()).isNull();
                                assertThat(record.createdAt()).isNotNull();
                                assertThat(record.updatedAt()).isNull();
                            });
        }

        @Test
        void shouldReturnEmptyListIfNoSecretsExists() {
            final var page = secretManager.listSecretMetadata(new ListSecretsRequest(null, null, 100));
            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount().value()).isEqualTo(0);
        }

        @Test
        void shouldSupportPagination() {
            secretManager.createSecret("alpha", null, "secret");
            secretManager.createSecret("beta", null, "secret");
            secretManager.createSecret("gamma", null, "secret");

            final var firstPage = secretManager.listSecretMetadata(
                    new ListSecretsRequest()
                            .withLimit(2));
            assertThat(firstPage.items()).extracting("name").containsExactly("alpha", "beta");
            assertThat(firstPage.nextPageToken()).isNotNull();
            assertThat(firstPage.totalCount().value()).isEqualTo(3);

            final var secondPage = secretManager.listSecretMetadata(
                    new ListSecretsRequest()
                            .withPageToken(firstPage.nextPageToken())
                            .withLimit(2));
            assertThat(secondPage.items()).extracting("name").containsExactly("gamma");
            assertThat(secondPage.nextPageToken()).isNull();
            assertThat(secondPage.totalCount().value()).isEqualTo(3);
        }

        @Test
        void shouldSupportSearchText() {
            secretManager.createSecret("alpha", null, "secret");
            secretManager.createSecret("beta", null, "secret");
            secretManager.createSecret("ALPHABET", null, "secret");

            final var page = secretManager.listSecretMetadata(
                    new ListSecretsRequest()
                            .withSearchText("alph"));
            assertThat(page.items()).extracting("name").containsExactly("ALPHABET", "alpha");
            assertThat(page.nextPageToken()).isNull();
            assertThat(page.totalCount().value()).isEqualTo(2);
        }

        @Test
        void shouldSupportSearchTextWithPagination() {
            secretManager.createSecret("foo1", null, "secret");
            secretManager.createSecret("foo2", null, "secret");
            secretManager.createSecret("foo3", null, "secret");
            secretManager.createSecret("bar1", null, "secret");

            final var firstPage = secretManager.listSecretMetadata(
                    new ListSecretsRequest()
                            .withSearchText("foo")
                            .withLimit(2));
            assertThat(firstPage.items()).extracting("name").containsExactly("foo1", "foo2");
            assertThat(firstPage.nextPageToken()).isNotNull();
            assertThat(firstPage.totalCount().value()).isEqualTo(3);

            final var secondPage = secretManager.listSecretMetadata(
                    new ListSecretsRequest()
                            .withSearchText("foo")
                            .withPageToken(firstPage.nextPageToken())
                            .withLimit(2));
            assertThat(secondPage.items()).extracting("name").containsExactly("foo3");
            assertThat(secondPage.nextPageToken()).isNull();
            assertThat(secondPage.totalCount().value()).isEqualTo(3);
        }

    }

    @Nested
    class KeyRotationTest {

        @Test
        void shouldSupportKekRotation() throws Exception {
            // Create a secret and ensure it can be decrypted.
            secretManager.createSecret("name", "description", "secret");
            assertThat(secretManager.getSecretValue("name")).isEqualTo("secret");

            // Add a new KEK and make it the primary key in the set.
            final KeysetHandle kekKeysetHandle =
                    TinkJsonProtoKeysetFormat.parseKeyset(
                            Files.readString(kekKeysetPath),
                            InsecureSecretKeyAccess.get());
            final var kekKeysetManager = KeysetManager.withKeysetHandle(kekKeysetHandle);
            kekKeysetManager.addNewKey(AeadKeyTemplates.AES128_GCM, /* asPrimary */ true);

            // Write the new KEK keyset to a separate file.
            final Path newKekKeysetFilePath = tempDir.resolve("new-kek-keyset.json");
            final String serializedKekKeyset =
                    TinkJsonProtoKeysetFormat.serializeKeyset(
                            kekKeysetManager.getKeysetHandle(),
                            InsecureSecretKeyAccess.get());
            Files.writeString(newKekKeysetFilePath, serializedKekKeyset);

            // Construct a new secret manager that uses the new KEK keyset.
            final Config config = new SmallRyeConfigBuilder()
                    .withDefaultValues(Map.ofEntries(
                            Map.entry("dt.datasource.secrets.url", postgresContainer.getJdbcUrl()),
                            Map.entry("dt.datasource.secrets.username", postgresContainer.getUsername()),
                            Map.entry("dt.datasource.secrets.password", postgresContainer.getPassword()),
                            Map.entry("dt.secret-management.database.datasource.name", "secrets"),
                            Map.entry("dt.secret-management.database.kek-keyset.path", newKekKeysetFilePath.toString()),
                            Map.entry("dt.secret-management.database.kek-keyset.create-if-missing", "false")))
                    .build();
            final var newSecretManagerFactory = new DatabaseSecretManagerProvider(dataSourceRegistry);

            try (final var newSecretManager = newSecretManagerFactory.create(config, new SimplePageTokenEncoder())) {
                // Verify that the existing secret can still be decrypted.
                assertThat(newSecretManager.getSecretValue("name")).isEqualTo("secret");

                // Verify that new secrets can be encrypted and decrypted.
                newSecretManager.createSecret("foo", "bar", "baz");
                assertThat(newSecretManager.getSecretValue("foo")).isEqualTo("baz");
            }

            // Verify that the secret manager using the old keyset
            // can't decrypt secrets encrypted with the new keyset.
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> secretManager.getSecretValue("foo"))
                    .withMessage("Failed to decrypt secret value");
        }

    }

    private record SecretRecord(
            String name,
            String description,
            String value,
            Timestamp createdAt,
            Timestamp updatedAt) {
    }

    private List<SecretRecord> getAllSecrets() throws Exception {
        final var records = new ArrayList<SecretRecord>();

        try (final Connection connection = postgresContainer.createConnection("");
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT *
                       FROM "SECRET"
                      ORDER BY "NAME"
                     """)) {
            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                records.add(new SecretRecord(
                        rs.getString("NAME"),
                        rs.getString("DESCRIPTION"),
                        rs.getString("VALUE"),
                        rs.getTimestamp("CREATED_AT"),
                        rs.getTimestamp("UPDATED_AT")));
            }
        }

        return records;
    }

}