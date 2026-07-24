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
package org.dependencytrack.pkgmetadata;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.PackageMetadataResolutionCandidateGroup;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "fetch-package-metadata-resolution-candidates")
public final class FetchPackageMetadataResolutionCandidatesActivity
        implements Activity<FetchPackageMetadataResolutionCandidatesArg, FetchPackageMetadataResolutionCandidatesRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(
            FetchPackageMetadataResolutionCandidatesActivity.class);
    private static final int DEFAULT_RESOLVE_BATCH_SIZE = 250;

    private final PluginManager pluginManager;
    private final int resolveBatchSize;

    public FetchPackageMetadataResolutionCandidatesActivity(PluginManager pluginManager) {
        this(pluginManager, DEFAULT_RESOLVE_BATCH_SIZE);
    }

    FetchPackageMetadataResolutionCandidatesActivity(
            PluginManager pluginManager,
            int resolveBatchSize) {
        this.pluginManager = pluginManager;
        this.resolveBatchSize = resolveBatchSize;
    }

    @Override
    public FetchPackageMetadataResolutionCandidatesRes execute(
            ActivityContext ctx,
            @Nullable FetchPackageMetadataResolutionCandidatesArg arg) {
        final Cursor cursor;
        try {
            cursor = Cursor.decode(arg != null ? arg.getCursor() : null);
        } catch (IllegalArgumentException e) {
            // An invalid cursor is irrecoverable.
            throw new TerminalApplicationFailureException(e);
        }

        final List<Candidate> fetchedDueCandidates = fetchDueCandidates(cursor, resolveBatchSize + 1);

        final boolean hasMore = fetchedDueCandidates.size() > resolveBatchSize;
        final List<Candidate> candidates = hasMore
                ? fetchedDueCandidates.subList(0, resolveBatchSize)
                : fetchedDueCandidates;
        final String nextCursor = hasMore
                ? Cursor.of(candidates.getLast()).encode()
                : null;

        final Collection<PackageMetadataResolverFactory> resolverFactories =
                pluginManager.getFactories(PackageMetadataResolver.class);

        final var purlsByResolver = new LinkedHashMap<String, List<String>>();

        for (final Candidate candidate : candidates) {
            final String purlStr = candidate.purl();
            final PackageURL purl;
            try {
                purl = new PackageURL(purlStr);
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL '{}'; Assigning to empty resolver", purlStr, e);
                purlsByResolver
                        .computeIfAbsent("", k -> new ArrayList<>())
                        .add(purlStr);
                continue;
            }

            String matchedResolverName = "";
            for (final PackageMetadataResolverFactory factory : resolverFactories) {
                if (factory.normalize(purl) != null) {
                    matchedResolverName = factory.extensionName();
                    break;
                }
            }

            purlsByResolver
                    .computeIfAbsent(matchedResolverName, k -> new ArrayList<>())
                    .add(purlStr);
        }

        final var resultBuilder = FetchPackageMetadataResolutionCandidatesRes.newBuilder();
        for (final Map.Entry<String, List<String>> entry : purlsByResolver.entrySet()) {
            resultBuilder.addCandidateGroups(
                    PackageMetadataResolutionCandidateGroup.newBuilder()
                            .setResolverName(entry.getKey())
                            .addAllPurls(entry.getValue())
                            .build());
        }
        if (nextCursor != null) {
            resultBuilder.setNextCursor(nextCursor);
        }

        return resultBuilder
                .setHasMore(hasMore)
                .build();
    }

    private List<Candidate> fetchDueCandidates(@Nullable Cursor cursor, int limit) {
        // Candidacy is derived from the PACKAGE_METADATA_RESOLUTION table,
        // which holds one row per unique PURL in the portfolio.
        //
        // A PURL is eligible if it was never resolved before,
        // or its last resolution was more than 24h ago.
        // Unresolvable PURLs are permanently skipped.
        //
        // Note that resolvers control their own caching strategy,
        // so not every due PURL triggers a remote lookup.
        return withJdbiHandle(handle -> handle
                .createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="cursorLastAttemptedAt" type="boolean" -->
                        <#-- @ftlvariable name="cursorPurl" type="boolean" -->
                        SELECT pmr."PURL"
                             , CAST(pmr."LAST_ATTEMPTED_AT" AS TEXT) AS "LAST_ATTEMPTED_AT"
                          FROM "PACKAGE_METADATA_RESOLUTION" AS pmr
                         WHERE pmr."STATUS" != 'UNRESOLVABLE'
                           AND pmr."LAST_ATTEMPTED_AT" <= NOW() - INTERVAL '24 hours'
                        <#if cursorLastAttemptedAt && cursorPurl>
                           AND (pmr."LAST_ATTEMPTED_AT", pmr."PURL") > (CAST(:cursorLastAttemptedAt AS TIMESTAMPTZ), :cursorPurl)
                        </#if>
                         ORDER BY pmr."LAST_ATTEMPTED_AT"
                                , pmr."PURL"
                         LIMIT :limit
                        """)
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .define(ATTRIBUTE_QUERY_NAME, "%s#fetchDueCandidates".formatted(getClass().getSimpleName()))
                .bind("cursorLastAttemptedAt", cursor != null ? cursor.lastAttemptedAt() : null)
                .bind("cursorPurl", cursor != null ? cursor.purl() : null)
                .bind("limit", limit)
                .defineNamedBindings()
                .map((rs, _) -> new Candidate(
                        rs.getString("PURL"),
                        rs.getString("LAST_ATTEMPTED_AT")))
                .list());
    }

    private record Candidate(String purl, String lastAttemptedAt) {
    }

    private record Cursor(String lastAttemptedAt, String purl) {

        private static final String DELIMITER = "\t";

        private static Cursor of(Candidate candidate) {
            return new Cursor(candidate.lastAttemptedAt(), candidate.purl());
        }

        private static @Nullable Cursor decode(@Nullable String encoded) {
            if (encoded == null || encoded.isEmpty()) {
                return null;
            }

            final int delimiterIndex = encoded.indexOf(DELIMITER);
            if (delimiterIndex < 0) {
                throw new IllegalArgumentException("Malformed resolution candidate cursor");
            }

            return new Cursor(
                    encoded.substring(0, delimiterIndex),
                    encoded.substring(delimiterIndex + DELIMITER.length()));
        }

        private String encode() {
            return "%s%s%s".formatted(lastAttemptedAt, DELIMITER, purl);
        }

    }

}
