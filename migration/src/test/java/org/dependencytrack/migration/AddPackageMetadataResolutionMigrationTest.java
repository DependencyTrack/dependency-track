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
package org.dependencytrack.migration;

import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class AddPackageMetadataResolutionMigrationTest {

    @Container
    private final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"))
                    .withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off")
                    .withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));

    @Test
    void shouldBackfillResolutionStatusFromExistingMetadata() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        // Migrate up to the previous schema version.
        new MigrationExecutor(dataSource, "202606292105").execute();

        // Seed component and package (artifact) metadata to migrate.
        try (final Connection connection = dataSource.getConnection();
             final Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO "PROJECT" ("NAME", "UUID")
                    VALUES ('acme-app', gen_random_uuid())
                    """);

            statement.execute("""
                    INSERT INTO "COMPONENT" ("PROJECT_ID", "NAME", "UUID", "PURL")
                    SELECT p."ID"
                         , c.name
                         , gen_random_uuid()
                         , c.purl
                      FROM "PROJECT" AS p
                     CROSS JOIN (
                       VALUES ('resolved', 'pkg:maven/com.acme/resolved@1.0.0')
                            , ('notfound', 'pkg:maven/com.acme/notfound@1.0.0')
                            , ('pending', 'pkg:maven/com.acme/pending@1.0.0')
                            -- Malformed PURLs have no metadata and must be backfilled
                            -- as PENDING. They're classified as UNRESOLVABLE during the next resolution.
                            , ('malformed', 'pkg:maven/com.acme/malformed%ZZ@1.0.0')
                            , ('no-purl', NULL)
                     ) AS c(name, purl)
                    """);

            statement.execute("""
                    INSERT INTO "PACKAGE_METADATA" ("PURL", "LATEST_VERSION", "RESOLVED_AT")
                    VALUES ('pkg:maven/com.acme/resolved', '2.0.0', TIMESTAMPTZ '2026-01-01T00:00:00Z')
                         , ('pkg:maven/com.acme/notfound', NULL, TIMESTAMPTZ '2026-02-02T00:00:00Z')
                    """);

            statement.execute("""
                    INSERT INTO "PACKAGE_ARTIFACT_METADATA" ("PURL", "PACKAGE_PURL", "RESOLVED_AT")
                    VALUES ('pkg:maven/com.acme/resolved@1.0.0', 'pkg:maven/com.acme/resolved', TIMESTAMPTZ '2026-01-01T00:00:00Z')
                         , ('pkg:maven/com.acme/notfound@1.0.0', 'pkg:maven/com.acme/notfound', TIMESTAMPTZ '2026-02-02T00:00:00Z')
                    """);
        }

        // Execute migration and backfill.
        new MigrationExecutor(dataSource, "202607211200").execute();

        final Map<String, ResolutionRow> rowByPurl = fetchResolutionRows(dataSource);
        assertThat(rowByPurl).containsOnlyKeys(
                "pkg:maven/com.acme/resolved@1.0.0",
                "pkg:maven/com.acme/notfound@1.0.0",
                "pkg:maven/com.acme/pending@1.0.0",
                "pkg:maven/com.acme/malformed%ZZ@1.0.0");

        assertThat(rowByPurl.get("pkg:maven/com.acme/resolved@1.0.0"))
                .isEqualTo(new ResolutionRow("RESOLVED", Instant.parse("2026-01-01T00:00:00Z")));
        assertThat(rowByPurl.get("pkg:maven/com.acme/notfound@1.0.0"))
                .isEqualTo(new ResolutionRow("NOT_FOUND", Instant.parse("2026-02-02T00:00:00Z")));
        assertThat(rowByPurl.get("pkg:maven/com.acme/pending@1.0.0"))
                .isEqualTo(new ResolutionRow("PENDING", Instant.EPOCH));
        assertThat(rowByPurl.get("pkg:maven/com.acme/malformed%ZZ@1.0.0"))
                .isEqualTo(new ResolutionRow("PENDING", Instant.EPOCH));
    }

    private record ResolutionRow(String status, Instant lastAttemptedAt) {
    }

    private static Map<String, ResolutionRow> fetchResolutionRows(PGSimpleDataSource dataSource) throws Exception {
        final var rowByPurl = new HashMap<String, ResolutionRow>();
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement statement = connection.prepareStatement("""
                     SELECT "PURL"
                          , "STATUS"
                          , "LAST_ATTEMPTED_AT"
                       FROM "PACKAGE_METADATA_RESOLUTION"
                     """);
             final ResultSet resultSet = statement.executeQuery()) {
            while (resultSet.next()) {
                final Timestamp lastAttemptedAt = resultSet.getTimestamp("LAST_ATTEMPTED_AT");
                rowByPurl.put(
                        resultSet.getString("PURL"),
                        new ResolutionRow(
                                resultSet.getString("STATUS"),
                                lastAttemptedAt != null
                                        ? lastAttemptedAt.toInstant()
                                        : null));
            }
        }

        return rowByPurl;
    }

}
