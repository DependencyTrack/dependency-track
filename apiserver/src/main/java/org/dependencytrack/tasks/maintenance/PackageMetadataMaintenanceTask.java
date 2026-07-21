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
package org.dependencytrack.tasks.maintenance;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/**
 * @since 5.0.0
 */
public final class PackageMetadataMaintenanceTask extends AbstractBatchingMaintenanceTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(PackageMetadataMaintenanceTask.class);
    private static final int BATCH_SIZE = 1000;
    private static final int MAX_ITERATIONS = 1000;

    public PackageMetadataMaintenanceTask() {
        super(MAX_ITERATIONS);
    }

    @Override
    public void run() {
        final int deletedArtifactMetadata = runBatched(
                BATCH_SIZE, PackageMetadataMaintenanceTask::deleteOrphanedArtifactMetadata);
        if (deletedArtifactMetadata > 0) {
            LOGGER.info("Deleted {} orphan PACKAGE_ARTIFACT_METADATA rows", deletedArtifactMetadata);
        }

        final int deletedPackageMetadata = runBatched(
                BATCH_SIZE, PackageMetadataMaintenanceTask::deleteOrphanedPackageMetadata);
        if (deletedPackageMetadata > 0) {
            LOGGER.info("Deleted {} orphan PACKAGE_METADATA rows", deletedPackageMetadata);
        }

        final int deletedResolutions = runBatched(
                BATCH_SIZE, PackageMetadataMaintenanceTask::deleteOrphanedResolutions);
        if (deletedResolutions > 0) {
            LOGGER.info("Deleted {} orphan PACKAGE_METADATA_RESOLUTION rows", deletedResolutions);
        }

        // Ensure every component PURL has a resolution row.
        // Eligibility for resolution is derived solely from PACKAGE_METADATA_RESOLUTION,
        // so a missing row means a PURL is never resolved.
        //
        // It can happen that a PURL is re-added while its row is being deleted,
        // or rows can never be added in the first place through operator actions
        // that bypass triggers (e.g. logical replication restore, disabled triggers).
        final int backfilledResolutions = backfillMissingResolutions();
        if (backfilledResolutions > 0) {
            LOGGER.info("Backfilled {} missing PACKAGE_METADATA_RESOLUTION rows", backfilledResolutions);
        }
    }

    private static int deleteOrphanedArtifactMetadata(Handle handle) {
        return handle
                .createUpdate("""
                        DELETE
                          FROM "PACKAGE_ARTIFACT_METADATA"
                         WHERE "PURL" IN (
                           SELECT "PURL"
                             FROM "PACKAGE_ARTIFACT_METADATA" AS pam
                            WHERE NOT EXISTS (
                              SELECT 1
                                FROM "COMPONENT" AS c
                               WHERE c."PURL" = pam."PURL"
                            )
                            LIMIT :batchSize
                         )
                        """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#deleteOrphanedArtifactMetadata".formatted(
                                PackageMetadataMaintenanceTask.class.getSimpleName()))
                .bind("batchSize", BATCH_SIZE)
                .execute();
    }

    private static int deleteOrphanedPackageMetadata(Handle handle) {
        return handle
                .createUpdate("""
                        DELETE
                          FROM "PACKAGE_METADATA"
                         WHERE "PURL" IN (
                           SELECT "PURL"
                             FROM "PACKAGE_METADATA" AS pm
                            WHERE NOT EXISTS (
                              SELECT 1
                                FROM "PACKAGE_ARTIFACT_METADATA" AS pam
                               WHERE pam."PACKAGE_PURL" = pm."PURL"
                            )
                            LIMIT :batchSize
                         )
                        """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#deleteOrphanedPackageMetadata".formatted(
                                PackageMetadataMaintenanceTask.class.getSimpleName()))
                .bind("batchSize", BATCH_SIZE)
                .execute();
    }

    private static int deleteOrphanedResolutions(Handle handle) {
        return handle
                .createUpdate("""
                        DELETE
                          FROM "PACKAGE_METADATA_RESOLUTION"
                         WHERE "PURL" IN (
                           SELECT "PURL"
                             FROM "PACKAGE_METADATA_RESOLUTION" AS r
                            WHERE NOT EXISTS (
                              SELECT 1
                                FROM "COMPONENT" AS c
                               WHERE c."PURL" = r."PURL"
                            )
                            LIMIT :batchSize
                         )
                        """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#deleteOrphanedResolutions".formatted(
                                PackageMetadataMaintenanceTask.class.getSimpleName()))
                .bind("batchSize", BATCH_SIZE)
                .execute();
    }

    private static int backfillMissingResolutions() {
        String cursor = null;
        int backfilled = 0;

        while (true) {
            final String pageCursor = cursor;
            final BackfillPage page = inJdbiTransaction(handle -> backfillPage(handle, pageCursor));

            backfilled += page.inserted();
            if (page.scanned() < BATCH_SIZE) {
                return backfilled;
            }

            cursor = page.lastPurl();
        }
    }

    private record BackfillPage(int scanned, int inserted, @Nullable String lastPurl) {
    }

    private static BackfillPage backfillPage(Handle handle, @Nullable String cursor) {
        return handle
                .createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="cursor" type="boolean" -->
                        WITH page AS (
                          SELECT DISTINCT "PURL"
                            FROM "COMPONENT"
                           WHERE "PURL" IS NOT NULL
                        <#if cursor>
                             AND "PURL" > :cursor
                        </#if>
                           ORDER BY "PURL"
                           LIMIT :batchSize
                        ), inserted AS (
                          INSERT INTO "PACKAGE_METADATA_RESOLUTION" ("PURL", "STATUS")
                          SELECT "PURL"
                               , 'PENDING'
                            FROM page
                           WHERE NOT EXISTS (
                             SELECT 1
                               FROM "PACKAGE_METADATA_RESOLUTION" AS pmr
                              WHERE pmr."PURL" = page."PURL"
                           )
                          ON CONFLICT ("PURL") DO NOTHING
                          RETURNING 1
                        )
                        SELECT (SELECT COUNT(*) FROM page) AS scanned
                             , (SELECT COUNT(*) FROM inserted) AS inserted
                             , (SELECT MAX("PURL") FROM page) AS last_purl
                        """)
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#backfillMissingResolutions".formatted(
                                PackageMetadataMaintenanceTask.class.getSimpleName()))
                .bind("cursor", cursor)
                .bind("batchSize", BATCH_SIZE)
                .defineNamedBindings()
                .map((rs, _) -> new BackfillPage(
                        rs.getInt("scanned"),
                        rs.getInt("inserted"),
                        rs.getString("last_purl")))
                .one();
    }

}
