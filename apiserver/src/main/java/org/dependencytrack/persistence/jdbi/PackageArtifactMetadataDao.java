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

import org.dependencytrack.model.PackageArtifactMetadata;
import org.jdbi.v3.core.Handle;

import java.sql.Timestamp;
import java.util.Collection;
import java.util.List;

/**
 * @since 5.0.0
 */
public final class PackageArtifactMetadataDao {

    private final Handle jdbiHandle;

    public PackageArtifactMetadataDao(Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public List<PackageArtifactMetadata> getAll(Collection<String> purls) {
        if (purls == null || purls.isEmpty()) {
            return List.of();
        }

        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        SELECT "PURL"
                             , "PACKAGE_PURL"
                             , "HASH_MD5"
                             , "HASH_SHA1"
                             , "HASH_SHA256"
                             , "HASH_SHA512"
                             , "PUBLISHED_AT"
                             , "RESOLVED_BY"
                             , "RESOLVED_FROM"
                             , "RESOLVED_AT"
                          FROM "PACKAGE_ARTIFACT_METADATA"
                         WHERE "PURL" = ANY(:purls)
                        """)
                .bindArray("purls", String.class, purls)
                .mapTo(PackageArtifactMetadata.class)
                .list();
    }

    public int upsertAll(Collection<PackageArtifactMetadata> metadata) {
        if (metadata.isEmpty()) {
            return 0;
        }

        final var purls = new String[metadata.size()];
        final var packagePurls = new String[metadata.size()];
        final var md5s = new String[metadata.size()];
        final var sha1s = new String[metadata.size()];
        final var sha256s = new String[metadata.size()];
        final var sha512s = new String[metadata.size()];
        final var publishedAts = new Timestamp[metadata.size()];
        final var resolvedBys = new String[metadata.size()];
        final var resolvedFroms = new String[metadata.size()];
        final var resolvedAts = new Timestamp[metadata.size()];

        int i = 0;
        for (final PackageArtifactMetadata pam : metadata) {
            purls[i] = pam.purl().canonicalize();
            packagePurls[i] = pam.packagePurl().canonicalize();
            md5s[i] = pam.md5();
            sha1s[i] = pam.sha1();
            sha256s[i] = pam.sha256();
            sha512s[i] = pam.sha512();
            publishedAts[i] = pam.publishedAt() != null
                    ? Timestamp.from(pam.publishedAt())
                    : null;
            resolvedBys[i] = pam.resolvedBy();
            resolvedFroms[i] = pam.resolvedFrom();
            resolvedAts[i] = pam.resolvedAt() != null
                    ? Timestamp.from(pam.resolvedAt())
                    : null;
            i++;
        }

        return jdbiHandle
                .createUpdate(/* language=SQL */ """
                        INSERT INTO "PACKAGE_ARTIFACT_METADATA" AS pam (
                          "PURL"
                        , "PACKAGE_PURL"
                        , "HASH_MD5"
                        , "HASH_SHA1"
                        , "HASH_SHA256"
                        , "HASH_SHA512"
                        , "PUBLISHED_AT"
                        , "RESOLVED_BY"
                        , "RESOLVED_FROM"
                        , "RESOLVED_AT"
                        )
                        SELECT *
                          FROM UNNEST(
                            :purls
                          , :packagePurls
                          , :md5s
                          , :sha1s
                          , :sha256s
                          , :sha512s
                          , :publishedAts
                          , :resolvedBys
                          , :resolvedFroms
                          , :resolvedAts
                          )
                         ORDER BY 1
                        ON CONFLICT ("PURL") DO UPDATE
                        SET "HASH_MD5" = COALESCE(EXCLUDED."HASH_MD5", pam."HASH_MD5")
                          , "HASH_SHA1" = COALESCE(EXCLUDED."HASH_SHA1", pam."HASH_SHA1")
                          , "HASH_SHA256" = COALESCE(EXCLUDED."HASH_SHA256", pam."HASH_SHA256")
                          , "HASH_SHA512" = COALESCE(EXCLUDED."HASH_SHA512", pam."HASH_SHA512")
                          , "PUBLISHED_AT" = COALESCE(EXCLUDED."PUBLISHED_AT", pam."PUBLISHED_AT")
                          , "RESOLVED_BY" = COALESCE(EXCLUDED."RESOLVED_BY", pam."RESOLVED_BY")
                          , "RESOLVED_FROM" = COALESCE(EXCLUDED."RESOLVED_FROM", pam."RESOLVED_FROM")
                          , "RESOLVED_AT" = EXCLUDED."RESOLVED_AT"
                        WHERE pam."RESOLVED_AT" < EXCLUDED."RESOLVED_AT"
                        """)
                .bind("purls", purls)
                .bind("packagePurls", packagePurls)
                .bind("md5s", md5s)
                .bind("sha1s", sha1s)
                .bind("sha256s", sha256s)
                .bind("sha512s", sha512s)
                .bind("publishedAts", publishedAts)
                .bind("resolvedBys", resolvedBys)
                .bind("resolvedFroms", resolvedFroms)
                .bind("resolvedAts", resolvedAts)
                .execute();
    }

}
