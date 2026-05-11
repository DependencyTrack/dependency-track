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
package org.dependencytrack.vulnanalysis.vulndb;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @since 5.0.0
 */
final class VulnDbVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbVulnAnalyzer.class);
    private static final JavaType VULNDB_VULNS_TYPE =
            TypeFactory.defaultInstance().constructCollectionType(List.class, VulnDbApiResponse.Vulnerability.class);
    private static final int CACHE_BATCH_SIZE = 500;

    private final Cache resultsCache;
    private final ObjectMapper objectMapper;
    private final VulnDbApiClient apiClient;
    private final boolean aliasSyncEnabled;

    VulnDbVulnAnalyzer(
            Cache resultsCache,
            ObjectMapper objectMapper,
            VulnDbApiClient apiClient,
            boolean aliasSyncEnabled) {
        this.resultsCache = resultsCache;
        this.objectMapper = objectMapper;
        this.apiClient = apiClient;
        this.aliasSyncEnabled = aliasSyncEnabled;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final Map<String, Set<String>> bomRefsByCpe = collectAnalyzableCpes(bom);
        if (bomRefsByCpe.isEmpty()) {
            LOGGER.debug("No analyzable CPEs found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final var vulnsByCpe = new HashMap<String, List<VulnDbApiResponse.Vulnerability>>(bomRefsByCpe.size());
        final var cpesToAnalyze = new LinkedHashSet<>(bomRefsByCpe.keySet());

        for (final var cpeBatch : partition(List.copyOf(bomRefsByCpe.keySet()), CACHE_BATCH_SIZE)) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all cache lookups could complete");
            }

            final Map<String, byte[]> cachedBytesByCpe = resultsCache.getMany(Set.copyOf(cpeBatch));
            LOGGER.debug("Found cached results for {}/{} CPEs", cachedBytesByCpe.size(), cpeBatch.size());

            for (final var entry : cachedBytesByCpe.entrySet()) {
                final String cpe = entry.getKey();
                final byte[] cachedBytes = entry.getValue();

                cpesToAnalyze.remove(cpe);

                if (cachedBytes == null) {
                    continue;
                }

                try {
                    vulnsByCpe.put(cpe, objectMapper.readValue(cachedBytes, VULNDB_VULNS_TYPE));
                } catch (IOException e) {
                    LOGGER.warn("Failed to deserialize cached results for CPE '{}'; Will re-fetch", cpe, e);
                    cpesToAnalyze.add(cpe);
                }
            }
        }

        vulnsByCpe.putAll(fetchAndCacheVulnerabilities(cpesToAnalyze));

        return assembleVdr(vulnsByCpe, bomRefsByCpe);
    }

    private Map<String, Set<String>> collectAnalyzableCpes(Bom bom) {
        final var bomRefsByCpe = new LinkedHashMap<String, Set<String>>();

        for (final Component component : bom.getComponentsList()) {
            if (!component.hasBomRef() || !component.hasCpe()) {
                continue;
            }
            if (component.getPropertiesCount() > 0
                    && component.getPropertiesList().stream()
                    .map(Property::getName)
                    .anyMatch("dependencytrack:internal:is-internal-component"::equalsIgnoreCase)) {
                continue;
            }

            bomRefsByCpe
                    .computeIfAbsent(component.getCpe(), k -> new HashSet<>())
                    .add(component.getBomRef());
        }

        return bomRefsByCpe;
    }

    private Map<String, List<VulnDbApiResponse.Vulnerability>> fetchAndCacheVulnerabilities(
            Collection<String> cpes) throws InterruptedException {
        if (cpes.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Fetching vulnerabilities for {} CPEs from VulnDB", cpes.size());

        final var entriesToCache = new HashMap<String, byte @Nullable []>(cpes.size());
        final var vulnsByCpe = new HashMap<String, List<VulnDbApiResponse.Vulnerability>>();

        for (final String cpe : cpes) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all CPEs could be analyzed");
            }

            final List<VulnDbApiResponse.Vulnerability> vulns;
            try {
                vulns = apiClient.getVulnerabilitiesByCpe(cpe);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to fetch vulnerabilities for CPE '%s'".formatted(cpe), e);
            }

            if (!vulns.isEmpty()) {
                vulnsByCpe.put(cpe, vulns);
                try {
                    entriesToCache.put(cpe, objectMapper.writeValueAsBytes(vulns));
                } catch (IOException e) {
                    LOGGER.warn("Failed to serialize results for CPE '{}'; Skipping cache", cpe, e);
                }
            } else {
                entriesToCache.put(cpe, null);
            }
        }

        resultsCache.putMany(entriesToCache);
        return vulnsByCpe;
    }

    private Bom assembleVdr(
            Map<String, List<VulnDbApiResponse.Vulnerability>> vulnsByCpe,
            Map<String, Set<String>> bomRefsByCpe) {
        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final var entry : vulnsByCpe.entrySet()) {
            final String cpe = entry.getKey();
            final List<VulnDbApiResponse.Vulnerability> vulnDbVulns = entry.getValue();

            final Set<String> bomRefs = bomRefsByCpe.get(cpe);
            if (bomRefs == null) {
                LOGGER.warn("""
                        Received vulnerabilities for CPE '{}', but no component \
                        with this CPE was submitted for analysis""", cpe);
                continue;
            }

            for (final var vulnDbVuln : vulnDbVulns) {
                final String vulnId = String.valueOf(vulnDbVuln.vulndbId());
                final Vulnerability.Builder vulnBuilder =
                        vulnBuilderByVulnId.computeIfAbsent(
                                vulnId,
                                ignored -> VulnDbModelConverter.convert(vulnDbVuln, aliasSyncEnabled));

                for (final String bomRef : bomRefs) {
                    vulnBuilder.addAffects(
                            VulnerabilityAffects.newBuilder()
                                    .setRef(bomRef)
                                    .build());
                }
            }
        }

        return Bom.newBuilder()
                .addAllVulnerabilities(
                        vulnBuilderByVulnId.values().stream()
                                .map(Vulnerability.Builder::build)
                                .toList())
                .build();
    }

    private static <T> List<List<T>> partition(List<T> list, int batchSize) {
        final var partitions = new ArrayList<List<T>>();
        for (int i = 0; i < list.size(); i += batchSize) {
            partitions.add(list.subList(i, Math.min(i + batchSize, list.size())));
        }
        return partitions;
    }

}
