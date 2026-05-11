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
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.util.PurlUtil;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.sql.Timestamp;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @since 5.7.0
 */
public final class PackageMetadataDao {

    private final Handle jdbiHandle;

    public PackageMetadataDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public @Nullable PackageMetadata get(PackageURL purl) {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT "PURL"
                             , "LATEST_VERSION"
                             , "LATEST_VERSION_PUBLISHED_AT"
                             , "RESOLVED_AT"
                             , "RESOLVED_FROM"
                             , "RESOLVED_BY"
                          FROM "PACKAGE_METADATA"
                         WHERE "PURL" = :purl
                        """)
                .bind("purl", PurlUtil.purlPackageOnly(purl))
                .mapTo(PackageMetadata.class)
                .findOne()
                .orElse(null);
    }

    public List<PackageMetadata> getAll(Collection<String> purls) {
        if (purls == null || purls.isEmpty()) {
            return Collections.emptyList();
        }

        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT "PURL"
                             , "LATEST_VERSION"
                             , "LATEST_VERSION_PUBLISHED_AT"
                             , "RESOLVED_AT"
                             , "RESOLVED_FROM"
                             , "RESOLVED_BY"
                          FROM "PACKAGE_METADATA"
                         WHERE "PURL" IN (SELECT UNNEST(:purls))
                        """)
                .bindArray("purls", String.class, purls)
                .mapTo(PackageMetadata.class)
                .list();
    }

    public int upsertAll(Collection<PackageMetadata> metadata) {
        if (metadata.isEmpty()) {
            return 0;
        }

        final var purls = new String[metadata.size()];
        final var latestVersions = new String[metadata.size()];
        final var latestVersionPublishedAts = new Timestamp[metadata.size()];
        final var resolvedAts = new Timestamp[metadata.size()];
        final var resolvedFroms = new String[metadata.size()];
        final var resolvedBys = new String[metadata.size()];

        int i = 0;
        for (final PackageMetadata pm : metadata) {
            purls[i] = pm.purl().canonicalize();
            latestVersions[i] = pm.latestVersion();
            latestVersionPublishedAts[i] = pm.latestVersionPublishedAt() != null
                ? Timestamp.from(pm.latestVersionPublishedAt())
                : null;
            resolvedAts[i] = Timestamp.from(pm.resolvedAt());
            resolvedFroms[i] = pm.resolvedFrom();
            resolvedBys[i] = pm.resolvedBy();
            i++;
        }

        return jdbiHandle
                .createUpdate(/* language=SQL */ """
                        INSERT INTO "PACKAGE_METADATA" AS pm (
                          "PURL"
                        , "LATEST_VERSION"
                        , "LATEST_VERSION_PUBLISHED_AT"
                        , "RESOLVED_AT"
                        , "RESOLVED_FROM"
                        , "RESOLVED_BY"
                        )
                        SELECT *
                          FROM UNNEST(
                            :purls
                          , :latestVersions
                          , :latestVersionPublishedAts
                          , :resolvedAts
                          , :resolvedFroms
                          , :resolvedBys
                          )
                         ORDER BY 1
                        ON CONFLICT ("PURL") DO UPDATE
                        SET "LATEST_VERSION" = COALESCE(EXCLUDED."LATEST_VERSION", pm."LATEST_VERSION")
                           , "LATEST_VERSION_PUBLISHED_AT" = CASE
                                WHEN EXCLUDED."LATEST_VERSION" IS NOT NULL
                                    AND EXCLUDED."LATEST_VERSION" IS DISTINCT FROM pm."LATEST_VERSION"
                                    THEN EXCLUDED."LATEST_VERSION_PUBLISHED_AT"
                                ELSE COALESCE(EXCLUDED."LATEST_VERSION_PUBLISHED_AT", pm."LATEST_VERSION_PUBLISHED_AT")
                                END
                           , "RESOLVED_AT" = EXCLUDED."RESOLVED_AT"
                           , "RESOLVED_FROM" = COALESCE(EXCLUDED."RESOLVED_FROM", pm."RESOLVED_FROM")
                           , "RESOLVED_BY" = COALESCE(EXCLUDED."RESOLVED_BY", pm."RESOLVED_BY")
                        WHERE pm."RESOLVED_AT" < EXCLUDED."RESOLVED_AT"
                        """)
                .bind("purls", purls)
                .bind("latestVersions", latestVersions)
                .bind("latestVersionPublishedAts", latestVersionPublishedAts)
                .bind("resolvedAts", resolvedAts)
                .bind("resolvedFroms", resolvedFroms)
                .bind("resolvedBys", resolvedBys)
                .execute();
    }

}
