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
package org.dependencytrack.persistence.jdbi;

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.pkgmetadata.PackageMetadata;
import org.dependencytrack.pkgmetadata.PackageMetadataDao;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class PackageHealthMetadataDaoTest extends PersistenceCapableTest {

    private static final Instant LAST_COMMIT = Instant.parse("2026-01-10T12:00:00Z");
    private static final Instant SCORECARD_TIMESTAMP = Instant.parse("2026-01-11T12:00:00Z");
    private static final Instant PROJECT_METADATA_OBSERVED_AT = Instant.ofEpochSecond(1658223503);
    private static final Instant LAST_FETCH = Instant.parse("2026-01-12T12:00:00Z");

    private Handle jdbiHandle;
    private PackageHealthMetadataDao healthMetadataDao;
    private PackageURL purl;

    @BeforeEach
    void beforeEach() throws Exception {
        jdbiHandle = openJdbiHandle();
        healthMetadataDao = new PackageHealthMetadataDao(jdbiHandle);

        purl = new PackageURL("pkg:maven/org.example/example");

        final var packageMetadataDao = new PackageMetadataDao(jdbiHandle);

        packageMetadataDao.upsertAll(List.of(
                new PackageMetadata(purl, "1.0.0", null, Instant.parse("2026-01-01T12:00:00Z"), "test", "test")));
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
    }

    @Test
    void shouldPersistAndRetrieveHealthMetadata() {
        final PackageHealthMetadata expected =
                createMetadata(100L, List.of(createCheck("Branch-Protection", 8.0f, List.of("detail-a", "detail-b"))));

        healthMetadataDao.upsertAll(List.of(expected));

        assertThat(healthMetadataDao.get(purl)).isEqualTo(expected);
    }

    @Test
    void shouldPersistNullableValues() {
        final var metadata = new PackageHealthMetadata(
                purl,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                PackageHealthMetadataStatus.NOT_AVAILABLE,
                List.of());

        healthMetadataDao.upsertAll(List.of(metadata));

        assertThat(healthMetadataDao.get(purl)).isEqualTo(metadata);
    }

    @Test
    void shouldUpdateMetadataAndReplaceScorecardChecks() {
        healthMetadataDao.upsertAll(List.of(createMetadata(
                100L,
                List.of(
                        createCheck("Branch-Protection", 8.0f, List.of("old-detail")),
                        createCheck("Code-Review", 7.0f, List.of())))));

        final PackageHealthMetadata updated = createMetadata(
                200L,
                List.of(
                        createCheck("Code-Review", 9.0f, List.of("updated-detail")),
                        createCheck("Vulnerabilities", 10.0f, List.of())));

        healthMetadataDao.upsertAll(List.of(updated));

        final PackageHealthMetadata actual = healthMetadataDao.get(purl);

        assertThat(actual).isEqualTo(updated);
        assertThat(actual.scorecardChecks())
                .extracting(PackageHealthScorecardCheck::name)
                .containsExactly("Code-Review", "Vulnerabilities");
    }

    @Test
    void shouldRemoveScorecardChecksWhenUpdatedWithEmptyList() {
        healthMetadataDao.upsertAll(
                List.of(createMetadata(100L, List.of(createCheck("Branch-Protection", 8.0f, List.of())))));

        final PackageHealthMetadata updated = createMetadata(200L, List.of());

        healthMetadataDao.upsertAll(List.of(updated));

        assertThat(healthMetadataDao.get(purl)).isEqualTo(updated);

        assertThat(countScorecardChecks()).isZero();
    }

    @Test
    void shouldReturnNullWhenHealthMetadataDoesNotExist() throws Exception {

        final var unknownPurl = new PackageURL("pkg:maven/org.example/unknown");

        assertThat(healthMetadataDao.get(unknownPurl)).isNull();
    }

    @Test
    void shouldCascadeDeleteHealthMetadataAndChecks() {
        healthMetadataDao.upsertAll(
                List.of(createMetadata(100L, List.of(createCheck("Branch-Protection", 8.0f, List.of())))));

        jdbiHandle.createUpdate("""
                        DELETE FROM "PACKAGE_METADATA"
                         WHERE "PURL" = :purl
                        """).bind("purl", purl.canonicalize()).execute();

        assertThat(healthMetadataDao.get(purl)).isNull();
        assertThat(countScorecardChecks()).isZero();
    }

    @Test
    void shouldPersistAndRetrieveMultiplePackagesWithTheirOwnChecks() throws Exception {
        final var otherPurl = new PackageURL("pkg:npm/other");
        new PackageMetadataDao(jdbiHandle)
                .upsertAll(List.of(new PackageMetadata(otherPurl, "2.0.0", null, LAST_FETCH, "test", "test")));

        final PackageHealthMetadata first =
                createMetadata(100L, List.of(createCheck("Branch-Protection", 8.0f, List.of("detail"))));
        final var otherCheck =
                new PackageHealthScorecardCheck(otherPurl, "Maintained", null, 2.0f, null, List.of(), null);
        final var second = new PackageHealthMetadata(
                otherPurl,
                5L,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                LAST_FETCH,
                PackageHealthMetadataStatus.PROCESSED,
                List.of(otherCheck));

        healthMetadataDao.upsertAll(List.of(second, first));

        final var actual = healthMetadataDao.getAll(List.of(
                new PackageURL("pkg:maven/org.example/example@1.0.0"),
                new PackageURL("pkg:npm/other@2.0.0"),
                new PackageURL("pkg:npm/unknown")));

        assertThat(actual).containsOnlyKeys(purl.canonicalize(), otherPurl.canonicalize());
        assertThat(actual.get(purl.canonicalize())).isEqualTo(first);
        assertThat(actual.get(otherPurl.canonicalize())).isEqualTo(second);
    }

    @Test
    void shouldSkipPackagesWhosePackageMetadataWasDeleted() throws Exception {
        // For example deleted by package metadata maintenance while the package was being fetched.
        final var deletedPurl = new PackageURL("pkg:npm/deleted");
        final var deleted = new AnalyzedPackageHealth(deletedPurl);
        deleted.setStars(1L);
        deleted.setScorecardChecks(
                List.of(new PackageHealthScorecardCheck(deletedPurl, "Maintained", null, 2.0f, null, List.of(), null)));
        final PackageHealthMetadata stored =
                createMetadata(100L, List.of(createCheck("Branch-Protection", 8.0f, List.of("detail"))));

        healthMetadataDao.upsertAll(
                List.of(deleted.toMetadata(PackageHealthMetadataStatus.PROCESSED, LAST_FETCH), stored));
        healthMetadataDao.recordFailedFetches(List.of(deletedPurl), LAST_FETCH);

        assertThat(healthMetadataDao.get(deletedPurl)).isNull();
        assertThat(healthMetadataDao.get(purl)).isEqualTo(stored);
        assertThat(countScorecardChecks()).isEqualTo(1);
    }

    private PackageHealthMetadata createMetadata(final Long stars, final List<PackageHealthScorecardCheck> checks) {

        return new PackageHealthMetadata(
                purl,
                stars,
                20L,
                15L,
                3.5f,
                12L,
                4L,
                LAST_COMMIT,
                3,
                true,
                true,
                true,
                200L,
                900L,
                false,
                8.7f,
                "v5.0.0",
                SCORECARD_TIMESTAMP,
                PROJECT_METADATA_OBSERVED_AT,
                "https://deps.dev/npm/example",
                "https://github.com/acme/example",
                6.5f,
                LAST_FETCH,
                PackageHealthMetadataStatus.PROCESSED,
                checks);
    }

    private PackageHealthScorecardCheck createCheck(final String name, final Float score, final List<String> details) {

        return new PackageHealthScorecardCheck(
                purl,
                name,
                "Description for " + name,
                score,
                "Reason for " + name,
                details,
                "https://example.com/" + name);
    }

    private int countScorecardChecks() {
        return jdbiHandle
                .createQuery("""
                        SELECT COUNT(*)
                          FROM "PACKAGE_HEALTH_SCORECARD_CHECK"
                         WHERE "PURL" = :purl
                        """)
                .bind("purl", purl.canonicalize())
                .mapTo(Integer.class)
                .one();
    }
}
