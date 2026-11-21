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
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.persistence.jdbi.mapping.PackageHealthMetadataRowMapper;
import org.dependencytrack.util.PurlUtil;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Provides persistence operations for package health metadata.
 *
 * @since 5.2.0
 */
@NullMarked
public final class PackageHealthMetadataDao {

    private final Handle jdbiHandle;

    public PackageHealthMetadataDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public @Nullable PackageHealthMetadata get(final PackageURL purl) {
        return getAll(List.of(purl)).get(PurlUtil.purlPackageOnly(purl));
    }

    /**
     * @return Health metadata by canonical package PURL
     */
    public Map<String, PackageHealthMetadata> getAll(final Collection<PackageURL> purls) {
        if (purls.isEmpty()) {
            return Map.of();
        }

        final Set<String> packagePurls =
                purls.stream().map(PurlUtil::purlPackageOnly).collect(Collectors.toSet());

        final Map<String, List<PackageHealthScorecardCheck>> checksByPurl = jdbiHandle
                .createQuery("""
                        SELECT "PURL"
                             , "CHECK_NAME"
                             , "DESCRIPTION"
                             , "SCORE"
                             , "REASON"
                             , "DETAILS"
                             , "DOCUMENTATION_URL"
                          FROM "PACKAGE_HEALTH_SCORECARD_CHECK"
                         WHERE "PURL" = ANY(:purls)
                         ORDER BY "PURL"
                                , "CHECK_NAME"
                        """)
                .bindArray("purls", String.class, packagePurls)
                .mapTo(PackageHealthScorecardCheck.class)
                .collect(Collectors.groupingBy(check -> check.purl().canonicalize()));

        return jdbiHandle
                .createQuery("""
                        SELECT "PURL"
                             , "STARS"
                             , "FORKS"
                             , "CONTRIBUTORS"
                             , "COMMIT_FREQUENCY_WEEKLY"
                             , "OPEN_ISSUES"
                             , "OPEN_PRS"
                             , "LAST_COMMIT"
                             , "BUS_FACTOR"
                             , "HAS_README"
                             , "HAS_CODE_OF_CONDUCT"
                             , "HAS_SECURITY_POLICY"
                             , "DEPENDENTS"
                             , "FILES"
                             , "IS_REPO_ARCHIVED"
                             , "SCORECARD_SCORE"
                             , "SCORECARD_REF_VERSION"
                             , "SCORECARD_TIMESTAMP"
                             , "PROJECT_METADATA_OBSERVED_AT"
                             , "DEPS_DEV_URL"
                             , "GITHUB_URL"
                             , "AVG_ISSUE_AGE_DAYS"
                             , "LAST_FETCH"
                             , "STATUS"
                          FROM "PACKAGE_HEALTH_METADATA"
                         WHERE "PURL" = ANY(:purls)
                        """)
                .bindArray("purls", String.class, packagePurls)
                .map(new PackageHealthMetadataRowMapper(checksByPurl))
                .collect(Collectors.toMap(metadata -> metadata.purl().canonicalize(), Function.identity()));
    }

    /**
     * Inserts or updates health metadata, and replaces its scorecard checks.
     * <p>
     * Packages whose package metadata no longer exists, for example because package metadata
     * maintenance deleted it during resolution, are skipped instead of failing the whole batch.
     */
    public void upsertAll(final Collection<PackageHealthMetadata> metadataList) {
        if (metadataList.isEmpty()) {
            return;
        }

        // Write in a stable order, so that concurrent writers lock rows in the same order.
        final List<PackageHealthMetadata> sortedMetadata = metadataList.stream()
                .sorted(Comparator.comparing(metadata -> metadata.purl().canonicalize()))
                .toList();

        jdbiHandle.useTransaction(handle -> {
            final List<PackageHealthMetadata> withPackageMetadata = withLockedPackageMetadata(handle, sortedMetadata);
            if (withPackageMetadata.isEmpty()) {
                return;
            }

            upsertMetadata(handle, withPackageMetadata);
            replaceScorecardChecks(handle, withPackageMetadata);
        });
    }

    /**
     * Locks the package metadata rows of the given health metadata until the transaction ends, so
     * that package metadata maintenance can not delete them in between.
     *
     * @return The health metadata whose package metadata exists
     */
    private static List<PackageHealthMetadata> withLockedPackageMetadata(
            final Handle handle, final List<PackageHealthMetadata> metadataList) {
        final Set<String> existingPurls = handle.createQuery("""
                        SELECT "PURL"
                          FROM "PACKAGE_METADATA"
                         WHERE "PURL" = ANY(:purls)
                         ORDER BY "PURL"
                           FOR KEY SHARE
                        """)
                .bindArray(
                        "purls",
                        String.class,
                        metadataList.stream()
                                .map(metadata -> PurlUtil.purlPackageOnly(metadata.purl()))
                                .toList())
                .mapTo(String.class)
                .collect(Collectors.toSet());

        return metadataList.stream()
                .filter(metadata -> existingPurls.contains(PurlUtil.purlPackageOnly(metadata.purl())))
                .toList();
    }

    /**
     * Records a fetch that failed, so that the package is not due again until its next refresh.
     * <p>
     * A package without a health record gets a {@link org.dependencytrack.model.PackageHealthMetadataStatus#NOT_AVAILABLE}
     * record. An existing record only gets the new fetch time and keeps its values, so that a failure
     * does not clear health that policies already act on.
     */
    public void recordFailedFetches(final Collection<PackageURL> purls, final Instant fetchedAt) {
        if (purls.isEmpty()) {
            return;
        }

        // Sorted for the same lock order as upsertAll.
        final List<String> packagePurls = purls.stream()
                .map(PurlUtil::purlPackageOnly)
                .distinct()
                .sorted()
                .toList();

        // Locks the package metadata rows, so that maintenance can not delete them before commit.
        jdbiHandle
                .createUpdate("""
                        INSERT INTO "PACKAGE_HEALTH_METADATA" ("PURL", "LAST_FETCH", "STATUS")
                        SELECT pm."PURL", :fetchedAt, 'NOT_AVAILABLE'
                          FROM "PACKAGE_METADATA" AS pm
                         WHERE pm."PURL" = ANY(:purls)
                         ORDER BY pm."PURL"
                           FOR KEY SHARE
                        ON CONFLICT ("PURL") DO UPDATE
                        SET "LAST_FETCH" = EXCLUDED."LAST_FETCH"
                        """)
                .bindArray("purls", String.class, packagePurls)
                .bind("fetchedAt", fetchedAt)
                .execute();
    }

    private static void upsertMetadata(final Handle handle, final List<PackageHealthMetadata> metadataList) {
        final PreparedBatch batch = handle.prepareBatch("""
                        INSERT INTO "PACKAGE_HEALTH_METADATA" (
                          "PURL"
                        , "STARS"
                        , "FORKS"
                        , "CONTRIBUTORS"
                        , "COMMIT_FREQUENCY_WEEKLY"
                        , "OPEN_ISSUES"
                        , "OPEN_PRS"
                        , "LAST_COMMIT"
                        , "BUS_FACTOR"
                        , "HAS_README"
                        , "HAS_CODE_OF_CONDUCT"
                        , "HAS_SECURITY_POLICY"
                        , "DEPENDENTS"
                        , "FILES"
                        , "IS_REPO_ARCHIVED"
                        , "SCORECARD_SCORE"
                        , "SCORECARD_REF_VERSION"
                        , "SCORECARD_TIMESTAMP"
                        , "PROJECT_METADATA_OBSERVED_AT"
                        , "DEPS_DEV_URL"
                        , "GITHUB_URL"
                        , "AVG_ISSUE_AGE_DAYS"
                        , "LAST_FETCH"
                        , "STATUS"
                        )
                        VALUES (
                          :purl
                        , :stars
                        , :forks
                        , :contributors
                        , :commitFrequencyWeekly
                        , :openIssues
                        , :openPullRequests
                        , :lastCommit
                        , :busFactor
                        , :hasReadme
                        , :hasCodeOfConduct
                        , :hasSecurityPolicy
                        , :dependents
                        , :files
                        , :repositoryArchived
                        , :scorecardScore
                        , :scorecardReferenceVersion
                        , :scorecardTimestamp
                        , :projectMetadataObservedAt
                        , :depsDevUrl
                        , :githubUrl
                        , :averageIssueAgeDays
                        , :lastFetch
                        , :status
                        )
                        ON CONFLICT ("PURL") DO UPDATE
                        SET "STARS" = EXCLUDED."STARS"
                          , "FORKS" = EXCLUDED."FORKS"
                          , "CONTRIBUTORS" = EXCLUDED."CONTRIBUTORS"
                          , "COMMIT_FREQUENCY_WEEKLY" = EXCLUDED."COMMIT_FREQUENCY_WEEKLY"
                          , "OPEN_ISSUES" = EXCLUDED."OPEN_ISSUES"
                          , "OPEN_PRS" = EXCLUDED."OPEN_PRS"
                          , "LAST_COMMIT" = EXCLUDED."LAST_COMMIT"
                          , "BUS_FACTOR" = EXCLUDED."BUS_FACTOR"
                          , "HAS_README" = EXCLUDED."HAS_README"
                          , "HAS_CODE_OF_CONDUCT" = EXCLUDED."HAS_CODE_OF_CONDUCT"
                          , "HAS_SECURITY_POLICY" = EXCLUDED."HAS_SECURITY_POLICY"
                          , "DEPENDENTS" = EXCLUDED."DEPENDENTS"
                          , "FILES" = EXCLUDED."FILES"
                          , "IS_REPO_ARCHIVED" = EXCLUDED."IS_REPO_ARCHIVED"
                          , "SCORECARD_SCORE" = EXCLUDED."SCORECARD_SCORE"
                          , "SCORECARD_REF_VERSION" = EXCLUDED."SCORECARD_REF_VERSION"
                          , "SCORECARD_TIMESTAMP" = EXCLUDED."SCORECARD_TIMESTAMP"
                          , "PROJECT_METADATA_OBSERVED_AT" = EXCLUDED."PROJECT_METADATA_OBSERVED_AT"
                          , "DEPS_DEV_URL" = EXCLUDED."DEPS_DEV_URL"
                          , "GITHUB_URL" = EXCLUDED."GITHUB_URL"
                          , "AVG_ISSUE_AGE_DAYS" = EXCLUDED."AVG_ISSUE_AGE_DAYS"
                          , "LAST_FETCH" = EXCLUDED."LAST_FETCH"
                          , "STATUS" = EXCLUDED."STATUS"
                        """);

        for (final PackageHealthMetadata metadata : metadataList) {
            batch.bind("purl", PurlUtil.purlPackageOnly(metadata.purl()))
                    .bind("stars", metadata.stars())
                    .bind("forks", metadata.forks())
                    .bind("contributors", metadata.contributors())
                    .bind("commitFrequencyWeekly", metadata.commitFrequencyWeekly())
                    .bind("openIssues", metadata.openIssues())
                    .bind("openPullRequests", metadata.openPullRequests())
                    .bind("lastCommit", metadata.lastCommit())
                    .bind("busFactor", metadata.busFactor())
                    .bind("hasReadme", metadata.hasReadme())
                    .bind("hasCodeOfConduct", metadata.hasCodeOfConduct())
                    .bind("hasSecurityPolicy", metadata.hasSecurityPolicy())
                    .bind("dependents", metadata.dependents())
                    .bind("files", metadata.files())
                    .bind("repositoryArchived", metadata.repositoryArchived())
                    .bind("scorecardScore", metadata.scorecardScore())
                    .bind("scorecardReferenceVersion", metadata.scorecardReferenceVersion())
                    .bind("scorecardTimestamp", metadata.scorecardTimestamp())
                    .bind("projectMetadataObservedAt", metadata.projectMetadataObservedAt())
                    .bind("depsDevUrl", metadata.depsDevUrl())
                    .bind("githubUrl", metadata.githubUrl())
                    .bind("averageIssueAgeDays", metadata.averageIssueAgeDays())
                    .bind("lastFetch", metadata.lastFetch())
                    .bind("status", metadata.status().name())
                    .add();
        }

        batch.execute();
    }

    private static void replaceScorecardChecks(final Handle handle, final List<PackageHealthMetadata> metadataList) {
        handle.createUpdate("""
                        DELETE FROM "PACKAGE_HEALTH_SCORECARD_CHECK"
                         WHERE "PURL" = ANY(:purls)
                        """)
                .bindArray(
                        "purls",
                        String.class,
                        metadataList.stream()
                                .map(metadata -> PurlUtil.purlPackageOnly(metadata.purl()))
                                .toList())
                .execute();

        final PreparedBatch batch = handle.prepareBatch("""
                INSERT INTO "PACKAGE_HEALTH_SCORECARD_CHECK" (
                  "PURL"
                , "CHECK_NAME"
                , "DESCRIPTION"
                , "SCORE"
                , "REASON"
                , "DETAILS"
                , "DOCUMENTATION_URL"
                )
                VALUES (
                  :purl
                , :checkName
                , :description
                , :score
                , :reason
                , :details
                , :documentationUrl
                )
                """);

        for (final PackageHealthMetadata metadata : metadataList) {
            final String packagePurl = PurlUtil.purlPackageOnly(metadata.purl());
            for (final PackageHealthScorecardCheck check : metadata.scorecardChecks()) {
                batch.bind("purl", packagePurl)
                        .bind("checkName", check.name())
                        .bind("description", check.description())
                        .bind("score", check.score())
                        .bind("reason", check.reason())
                        .bindArray("details", String.class, check.details())
                        .bind("documentationUrl", check.documentationUrl())
                        .add();
            }
        }

        if (batch.size() > 0) {
            batch.execute();
        }
    }
}
