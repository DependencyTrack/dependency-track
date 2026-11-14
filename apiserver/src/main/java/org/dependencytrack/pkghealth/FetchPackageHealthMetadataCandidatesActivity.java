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
package org.dependencytrack.pkghealth;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesRes;
import org.dependencytrack.util.PurlUtil;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@ActivitySpec(name = "fetch-package-health-metadata-candidates")
public final class FetchPackageHealthMetadataCandidatesActivity
        implements Activity<FetchPackageHealthMetadataCandidatesArg, FetchPackageHealthMetadataCandidatesRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(FetchPackageHealthMetadataCandidatesActivity.class);
    private static final int DEFAULT_BATCH_SIZE = 25;

    private final List<String> purlPrefixes;
    private final int batchSize;

    public FetchPackageHealthMetadataCandidatesActivity(final PackageHealthAnalyzer analyzer) {
        this(analyzer, DEFAULT_BATCH_SIZE);
    }

    FetchPackageHealthMetadataCandidatesActivity(final PackageHealthAnalyzer analyzer, final int batchSize) {
        // Packages of other types would never get a health row, and would be selected again on every run.
        this.purlPrefixes = analyzer.supportedPurlTypes().stream()
                .map(type -> "pkg:" + type + "/%")
                .sorted()
                .toList();
        this.batchSize = batchSize;
    }

    @Override
    public FetchPackageHealthMetadataCandidatesRes execute(
            final ActivityContext ctx, final @Nullable FetchPackageHealthMetadataCandidatesArg arg) {
        // Checked for every batch, so that turning the setting off also stops a run in progress.
        if (!withJdbiHandle(PackageHealthSettings::isEnabled)) {
            LOGGER.info("Package health metadata resolution is disabled");
            return FetchPackageHealthMetadataCandidatesRes.getDefaultInstance();
        }

        final Cursor cursor;
        try {
            cursor = Cursor.decode(arg != null ? arg.getCursor() : null);
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException(e);
        }

        final List<Candidate> fetched = fetchDueCandidates(cursor, batchSize + 1);

        final boolean hasMore = fetched.size() > batchSize;
        final List<Candidate> page = hasMore ? fetched.subList(0, batchSize) : fetched;

        final var purls = new ArrayList<String>(page.size());
        for (final Candidate candidate : page) {
            if (PurlUtil.silentPurl(candidate.purl()) != null) {
                purls.add(candidate.purl());
            } else {
                LOGGER.warn("Failed to parse package health candidate PURL '{}'", candidate.purl());
            }
        }

        final var result = FetchPackageHealthMetadataCandidatesRes.newBuilder()
                .addAllPurls(purls)
                .setHasMore(hasMore);

        if (hasMore) {
            result.setNextCursor(Cursor.of(page.getLast()).encode());
        }

        return result.build();
    }

    private List<Candidate> fetchDueCandidates(final @Nullable Cursor cursor, final int limit) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT pm."PURL"
                             , COALESCE(
                                   phm."LAST_FETCH",
                                   TIMESTAMPTZ 'epoch'
                               ) AS "LAST_FETCH"
                          FROM "PACKAGE_METADATA" AS pm
                          LEFT JOIN "PACKAGE_HEALTH_METADATA" AS phm
                            ON phm."PURL" = pm."PURL"
                         WHERE pm."PURL" LIKE ANY(:purlPrefixes)
                           AND (
                                   phm."PURL" IS NULL
                                OR phm."LAST_FETCH"
                                   <= NOW() - INTERVAL '24 hours'
                               )
                        <#if cursorLastFetch && cursorPurl>
                           AND (
                                   COALESCE(
                                       phm."LAST_FETCH",
                                       TIMESTAMPTZ 'epoch'
                                   ),
                                   pm."PURL"
                               ) > (
                                   CAST(:cursorLastFetch AS TIMESTAMPTZ),
                                   :cursorPurl
                               )
                        </#if>
                         ORDER BY COALESCE(
                                      phm."LAST_FETCH",
                                      TIMESTAMPTZ 'epoch'
                                  )
                                , pm."PURL"
                         LIMIT :limit
                        """)
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#fetchDueCandidates".formatted(getClass().getSimpleName()))
                .bindArray("purlPrefixes", String.class, purlPrefixes)
                .bind("cursorLastFetch", cursor != null ? cursor.lastFetch() : null)
                .bind("cursorPurl", cursor != null ? cursor.purl() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .map((rs, _) -> new Candidate(
                        rs.getString("PURL"),
                        rs.getObject("LAST_FETCH", OffsetDateTime.class).toInstant()))
                .list());
    }

    private record Candidate(String purl, Instant lastFetch) {}

    private record Cursor(Instant lastFetch, String purl) {

        private static final String DELIMITER = "\t";

        private static Cursor of(final Candidate candidate) {
            return new Cursor(candidate.lastFetch(), candidate.purl());
        }

        private static @Nullable Cursor decode(final @Nullable String encoded) {
            if (encoded == null || encoded.isEmpty()) {
                return null;
            }

            final int delimiterIndex = encoded.indexOf(DELIMITER);
            if (delimiterIndex < 0) {
                throw new IllegalArgumentException("Malformed package health candidate cursor");
            }

            try {
                return new Cursor(
                        Instant.parse(encoded.substring(0, delimiterIndex)),
                        encoded.substring(delimiterIndex + DELIMITER.length()));
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("Malformed timestamp in package health candidate cursor", e);
            }
        }

        private String encode() {
            return "%s%s%s".formatted(lastFetch, DELIMITER, purl);
        }
    }
}
