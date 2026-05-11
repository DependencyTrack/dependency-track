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
package org.dependencytrack.vulnanalysis.ossindex;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
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
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
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
final class OssIndexVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexVulnAnalyzer.class);
    private static final JavaType COMPONENT_REPORTS_TYPE =
            TypeFactory.defaultInstance().constructCollectionType(List.class, ComponentReport.class);
    private static final JavaType REPORTED_VULNS_TYPE =
            TypeFactory.defaultInstance().constructCollectionType(List.class, ComponentReportVulnerability.class);
    private static final int REQUEST_BATCH_SIZE = 128;
    private static final int CACHE_BATCH_SIZE = 500;
    private static final Set<String> SUPPORTED_PURL_TYPES = Set.of(
            "cargo", "cocoapods", "composer", "conan", "conda",
            "cran", "gem", "golang", "maven", "npm", "nuget",
            "pypi", "rpm", "swift");

    private final Cache resultsCache;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiUrl;
    private final String authHeaderValue;
    private final boolean aliasSyncEnabled;

    OssIndexVulnAnalyzer(
            Cache resultsCache,
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiUrl,
            String username,
            String apiToken,
            boolean aliasSyncEnabled) {
        this.resultsCache = resultsCache;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiUrl = apiUrl;
        if (username != null && apiToken != null) {
            final String basicAuthCredentials = Base64.getEncoder().encodeToString(
                    "%s:%s".formatted(username, apiToken).getBytes(StandardCharsets.UTF_8));
            this.authHeaderValue = "Basic " + basicAuthCredentials;
        } else {
            this.authHeaderValue = "Bearer " + apiToken;
        }
        this.aliasSyncEnabled = aliasSyncEnabled;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final Map<String, Set<String>> bomRefsByPurl = collectAnalyzablePurls(bom);
        if (bomRefsByPurl.isEmpty()) {
            LOGGER.debug("No analyzable PURLs found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final var reportedVulnsByPurl = new HashMap<String, List<ComponentReportVulnerability>>(bomRefsByPurl.size());
        final var purlsToAnalyze = new LinkedHashSet<>(bomRefsByPurl.keySet());

        // Try to populate results from cache.
        // Do so in batches as to not overwhelm cache providers.
        for (final var purlBatch : partition(List.copyOf(bomRefsByPurl.keySet()), CACHE_BATCH_SIZE)) {
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
                    reportedVulnsByPurl.put(purl, objectMapper.readValue(cachedBytes, REPORTED_VULNS_TYPE));
                } catch (IOException e) {
                    LOGGER.warn("Failed to deserialize cached component report for PURL '{}'; Will re-fetch", purl, e);
                    purlsToAnalyze.add(entry.getKey());
                }
            }
        }

        reportedVulnsByPurl.putAll(analyzePurls(purlsToAnalyze));

        return assembleVdr(reportedVulnsByPurl, bomRefsByPurl);
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
                if (!SUPPORTED_PURL_TYPES.contains(purl.getType())) {
                    continue;
                }

                bomRefsByPurl
                        .computeIfAbsent(purl.getCoordinates(), k -> new HashSet<>())
                        .add(component.getBomRef());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL '{}'; Skipping", component.getPurl(), e);
            }
        }

        return bomRefsByPurl;
    }

    private Map<String, List<ComponentReportVulnerability>> analyzePurls(
            Collection<String> purls) throws InterruptedException {
        if (purls.isEmpty()) {
            return Map.of();
        }

        final var reportedVulnsByPurl = new HashMap<String, List<ComponentReportVulnerability>>(purls.size());

        for (final var purlBatch : partition(List.copyOf(purls), REQUEST_BATCH_SIZE)) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            reportedVulnsByPurl.putAll(analyzePurlBatch(purlBatch));
        }

        return reportedVulnsByPurl;
    }

    private Map<String, List<ComponentReportVulnerability>> analyzePurlBatch(
            Collection<String> purlBatch) throws InterruptedException {
        if (purlBatch.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Fetching component reports for {} PURLs", purlBatch.size());

        final List<ComponentReport> batchReports;
        try {
            batchReports = getComponentReports(purlBatch);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to retrieve component report", e);
        }

        final var reportedVulnsByPurl = new HashMap<String, List<ComponentReportVulnerability>>(batchReports.size());
        final var entriesToCache = new HashMap<String, byte @Nullable []>(purlBatch.size());

        for (final var report : batchReports) {
            if (report.vulnerabilities() != null && !report.vulnerabilities().isEmpty()) {
                reportedVulnsByPurl.put(report.coordinates(), report.vulnerabilities());
                try {
                    entriesToCache.put(report.coordinates(), objectMapper.writeValueAsBytes(report.vulnerabilities()));
                } catch (IOException e) {
                    LOGGER.warn("Failed to serialize component report for PURL '{}'; Skipping cache", report.coordinates(), e);
                }
            }
        }

        for (final String purl : purlBatch) {
            if (!reportedVulnsByPurl.containsKey(purl)) {
                entriesToCache.put(purl, null);
            }
        }

        resultsCache.putMany(entriesToCache);
        return reportedVulnsByPurl;
    }

    private List<ComponentReport> getComponentReports(Collection<String> coordinates) throws InterruptedException, IOException {
        if (coordinates.isEmpty()) {
            return List.of();
        }

        final var requestBody = new ComponentReportRequest(coordinates);
        final byte[] requestBytes = objectMapper.writeValueAsBytes(requestBody);

        final var request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl + "/api/v3/component-report"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", authHeaderValue)
                .timeout(Duration.ofSeconds(10))
                .POST(BodyPublishers.ofByteArray(requestBytes))
                .build();

        final HttpResponse<InputStream> response = httpClient.send(request, BodyHandlers.ofInputStream());

        try (final InputStream bodyInputStream = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(bodyInputStream, COMPONENT_REPORTS_TYPE);
            }

            throw new IOException("OSS Index API request failed with status " + response.statusCode());
        }
    }

    private Bom assembleVdr(
            Map<String, List<ComponentReportVulnerability>> reportedVulnsByPurl,
            Map<String, Set<String>> bomRefsByPurl) {
        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final var entry : reportedVulnsByPurl.entrySet()) {
            final String purl = entry.getKey();
            final List<ComponentReportVulnerability> reportedVulns = entry.getValue();

            final Set<String> bomRefs = bomRefsByPurl.get(purl);
            if (bomRefs == null) {
                LOGGER.warn("""
                        Received vulnerabilities for PURL '{}', but no component \
                        with this PURL was submitted for analysis""", purl);
                continue;
            }

            for (final var reportedVuln : reportedVulns) {
                final Vulnerability.Builder vulnBuilder =
                        vulnBuilderByVulnId.computeIfAbsent(
                                reportedVuln.id(),
                                ignored -> OssIndexModelConverter.convert(reportedVuln, aliasSyncEnabled));

                for (final String bomRef : bomRefs) {
                    vulnBuilder.addAffects(
                            VulnerabilityAffects.newBuilder()
                                    .setRef(bomRef)
                                    .build());
                }
            }
        }

        return Bom
                .newBuilder()
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
