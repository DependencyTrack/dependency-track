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
package org.dependencytrack.vulnanalysis.checkmarx;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
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
import java.util.stream.Gatherers;

/**
 * Checkmarx vulnerability analyzer for Dependency-Track.
 * Analyzes components for vulnerabilities using Checkmarx SCA API.
 */
final class CheckmarxVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(CheckmarxVulnAnalyzer.class);
    private static final int REQUEST_BATCH_SIZE = 100;
    private static final int CACHE_BATCH_SIZE = 500;

    private final Cache resultsCache;
    private final ObjectMapper objectMapper;
    private final CheckmarxApiClient apiClient;
    private final boolean aliasSyncEnabled;

    CheckmarxVulnAnalyzer(
            Cache resultsCache,
            ObjectMapper objectMapper,
            CheckmarxApiClient apiClient,
            boolean aliasSyncEnabled) {
        this.resultsCache = resultsCache;
        this.objectMapper = objectMapper;
        this.apiClient = apiClient;
        this.aliasSyncEnabled = aliasSyncEnabled;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final Map<String, Set<String>> bomRefsByPurl = collectAnalyzablePurls(bom);
        if (bomRefsByPurl.isEmpty()) {
            LOGGER.debug("No analyzable PURLs found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final var vulnerabilitiesByPurl = new HashMap<String, List<CheckmarxDataObject>>(bomRefsByPurl.size());
        final var purlsToAnalyze = new LinkedHashSet<>(bomRefsByPurl.keySet());

        for (final var purlBatch : (Iterable<List<String>>) () -> bomRefsByPurl.keySet().stream()
                .gather(Gatherers.windowFixed(CACHE_BATCH_SIZE))
                .iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all cache lookups could complete");
            }

            final Map<String, byte[]> cachedBytesByPurl = resultsCache.getMany(Set.copyOf(purlBatch));
            LOGGER.debug("Found cached results for {}/{} PURLs", cachedBytesByPurl.size(), purlBatch.size());

            for (final var entry : cachedBytesByPurl.entrySet()) {
                final String purl = entry.getKey();
                final byte[] cachedBytes = entry.getValue();

                purlsToAnalyze.remove(purl);

                if (cachedBytes == null) {
                    continue;
                }

                try {
                    final CheckmarxDataObject[] cxDataObjects = objectMapper.readValue(cachedBytes, CheckmarxDataObject[].class);
                    vulnerabilitiesByPurl.put(purl, List.of(cxDataObjects));
                } catch (IOException e) {
                    LOGGER.warn("Failed to deserialize cached results for PURL '{}'; Will re-fetch", purl, e);
                    purlsToAnalyze.add(purl);
                }
            }
        }

        vulnerabilitiesByPurl.putAll(analyzePurls(purlsToAnalyze, bomRefsByPurl));

        return assembleVdr(vulnerabilitiesByPurl, bomRefsByPurl);
    }

    private Map<String,? extends List<CheckmarxDataObject>> analyzePurls(
            Collection<String> purls,
            Map<String, Set<String>> bomRefsByPurl) throws InterruptedException {
        if (purls.isEmpty()) {
            return Map.of();
        }

        final var vulnerabilitiesByPurl = new HashMap<String, List<CheckmarxDataObject>>(purls.size());
        for (final var purlBatch : (Iterable<List<String>>) () -> purls.stream()
                .gather(Gatherers.windowFixed(REQUEST_BATCH_SIZE))
                .iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            vulnerabilitiesByPurl.putAll(analyzePurlBatch(purlBatch, bomRefsByPurl));
        }

        return vulnerabilitiesByPurl;
    }

    private Map<String,? extends List<CheckmarxDataObject>> analyzePurlBatch(
            Collection<String> purlBatch,
            Map<String, Set<String>> bomRefsByPurl) throws InterruptedException {
        if (purlBatch.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Fetching vulnerabilities for {} PURLs from Checkmarx", purlBatch.size());

        final CheckmarxApiResponse  response;
        try {
            response = apiClient.fetchVulnerabilities(purlBatch);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to fetch Checkmarx vulnerabilities", e);
        }

        final var vulnerabilitiesByPurl = new HashMap<String, List<CheckmarxDataObject>>();
        final var entriesToCache = new HashMap<String, byte @Nullable []>(purlBatch.size());

        if (response.data() != null && !response.data().isEmpty()) {
            for (final CheckmarxDataObject cxDataObject : response.data()) {
                final String vulnPurl = cxDataObject.pkg().purl();
                if (vulnPurl == null) {
                    LOGGER.warn("Unable to extract PURL for package '{}:{}'; Skipping", cxDataObject.pkg().name(), cxDataObject.pkg().version());
                    continue;
                }

                final String vulnPurlLower = vulnPurl.toLowerCase();
                if (!bomRefsByPurl.containsKey(vulnPurlLower)) {
                    LOGGER.warn("Received vulnerability data for PURL '{}', but no component with this PURL was submitted", vulnPurl);
                    continue;
                }

                vulnerabilitiesByPurl
                        .computeIfAbsent(vulnPurlLower, _ -> new ArrayList<>())
                        .add(cxDataObject);
            }
        }

        for (final var entry : vulnerabilitiesByPurl.entrySet()) {
            try {
                entriesToCache.put(entry.getKey(), objectMapper.writeValueAsBytes(entry.getValue()));
            } catch (IOException e) {
                LOGGER.warn("Failed to serialize data for PURL '{}'; Skipping cache", entry.getKey(), e);
            }
        }

        for (final String purl : purlBatch) {
            if (!vulnerabilitiesByPurl.containsKey(purl)) {
                entriesToCache.put(purl, null);
            }
        }

        resultsCache.putMany(entriesToCache);
        return vulnerabilitiesByPurl;
    }

    private Map<String, Set<String>> collectAnalyzablePurls(Bom bom) {
        final var bomRefsByPurl = new LinkedHashMap<String, Set<String>>();

        for (final Component component : bom.getComponentsList()) {
            if (!component.hasBomRef() || !component.hasPurl()) {
                continue;
            }
            if (component.getPropertiesCount() > 0
                    && component.getPropertiesList().stream()
                    .map(Property::getName)
                    .anyMatch("dependencytrack:internal:is-internal-component"::equalsIgnoreCase)) {
                continue;
            }

            try {
                final var purl = new PackageURL(component.getPurl());
                // Lowercase PURL coordinates for consistent cache keys
                bomRefsByPurl
                        .computeIfAbsent(purl.getCoordinates().toLowerCase(), _ -> new HashSet<>())
                        .add(component.getBomRef());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL '{}'; Skipping", component.getPurl(), e);
            }
        }

        return bomRefsByPurl;
    }

    private Bom assembleVdr(
            Map<String, List<CheckmarxDataObject>> vulnerabilitiesByPurl,
            Map<String, Set<String>> bomRefsByPurl) {
        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final var entry : vulnerabilitiesByPurl.entrySet()) {
            final String purl = entry.getKey();
            final List<CheckmarxDataObject> cxDataObjects = entry.getValue();

            final Set<String> bomRefs = bomRefsByPurl.get(purl);
            if (bomRefs == null) {
                LOGGER.warn("""
                        Received vulnerabilities for PURL '{}', but no component \
                        with this PURL was submitted for analysis""", purl);
                continue;
            }

            for (final CheckmarxDataObject cxObject : cxDataObjects) {
                cxObject.vulnerabilities().forEach(cxVuln -> {
                    final Vulnerability.Builder vulnBuilder =
                            vulnBuilderByVulnId.computeIfAbsent(
                                    cxVuln.cxId(),
                                    _ -> CheckmarxModelConverter.convert(cxVuln, cxObject.pkg().remediation(), aliasSyncEnabled));

                    for (final String bomRef : bomRefs) {
                        vulnBuilder.addAffects(
                                VulnerabilityAffects.newBuilder()
                                        .setRef(bomRef)
                                        .build());
                    }
                });
            }
        }

        return Bom.newBuilder()
                .addAllVulnerabilities(
                        vulnBuilderByVulnId.values().stream()
                                .map(Vulnerability.Builder::build)
                                .toList())
                .build();
    }
}
