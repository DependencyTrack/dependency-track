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
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.PackageMetadataResolutionCandidateGroup;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "fetch-package-metadata-resolution-candidates")
public final class FetchPackageMetadataResolutionCandidatesActivity
        implements Activity<Void, FetchPackageMetadataResolutionCandidatesRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(
            FetchPackageMetadataResolutionCandidatesActivity.class);
    private static final int BATCH_SIZE = 250;

    private final PluginManager pluginManager;

    public FetchPackageMetadataResolutionCandidatesActivity(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    public FetchPackageMetadataResolutionCandidatesRes execute(
            ActivityContext ctx,
            @Nullable Void arg) {
        final List<String> purls = fetchCandidatePurls(BATCH_SIZE);

        final Collection<PackageMetadataResolverFactory> resolverFactories =
                pluginManager.getFactories(PackageMetadataResolver.class);

        final var purlsByResolver = new LinkedHashMap<String, List<String>>();

        for (final String purlStr : purls) {
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

        return resultBuilder.build();
    }

    private static List<String> fetchCandidatePurls(int limit) {
        // A PURL is eligible for metadata resolution if:
        //   * No artifact metadata record exists for it, or
        //   * No package metadata record exists for it, or
        //   * Package metadata was last resolved over 24h ago
        // Note that resolvers control their own caching strategy,
        // so not every PURL that becomes eligible for resolution
        // will actually trigger a remote repository lookup.
        return withJdbiHandle(handle -> handle
                .createQuery(/* language=SQL */ """
                        SELECT DISTINCT c."PURL"
                          FROM "COMPONENT" c
                         WHERE c."PURL" IS NOT NULL
                           AND NOT EXISTS (
                             SELECT 1
                               FROM "PACKAGE_ARTIFACT_METADATA" pam
                               JOIN "PACKAGE_METADATA" pm
                                 ON pm."PURL" = pam."PACKAGE_PURL"
                              WHERE pam."PURL" = c."PURL"
                                AND pm."RESOLVED_AT" > NOW() - INTERVAL '24 hours'
                           )
                         ORDER BY c."PURL"
                         LIMIT :limit
                        """)
                .bind("limit", limit)
                .mapTo(String.class)
                .list());
    }

}
