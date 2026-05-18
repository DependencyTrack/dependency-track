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
package org.dependencytrack.vulnanalysis.snyk;

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
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
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
 * @since 5.0.0
 */
final class SnykVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(SnykVulnAnalyzer.class);
    private static final int REQUEST_BATCH_SIZE = 100;
    private static final int CACHE_BATCH_SIZE = 500;
    private static final Set<String> SUPPORTED_PURL_TYPES = Set.of(
            "cargo", "cocoapods", "composer", "gem", "generic",
            "hex", "maven", "npm", "nuget", "pypi", "swift", "golang");

    private final Cache resultsCache;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiBaseUrl;
    private final String orgId;
    private final String apiToken;
    private final String apiVersion;
    private final boolean aliasSyncEnabled;

    SnykVulnAnalyzer(
            Cache resultsCache,
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiBaseUrl,
            String orgId,
            String apiToken,
            String apiVersion,
            boolean aliasSyncEnabled) {
        this.resultsCache = resultsCache;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiBaseUrl = apiBaseUrl;
        this.orgId = orgId;
        this.apiToken = apiToken;
        this.apiVersion = apiVersion;
        this.aliasSyncEnabled = aliasSyncEnabled;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final Map<String, Set<String>> bomRefsByPurl = collectAnalyzablePurls(bom);
        if (bomRefsByPurl.isEmpty()) {
            LOGGER.debug("No analyzable PURLs found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final var issuesByPurl = new HashMap<String, List<SnykIssue>>(bomRefsByPurl.size());
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
                    final SnykIssue[] issues = objectMapper.readValue(cachedBytes, SnykIssue[].class);
                    issuesByPurl.put(purl, List.of(issues));
                } catch (IOException e) {
                    LOGGER.warn("Failed to deserialize cached issues for PURL '{}'; Will re-fetch", purl, e);
                    purlsToAnalyze.add(purl);
                }
            }
        }

        issuesByPurl.putAll(analyzePurls(purlsToAnalyze, bomRefsByPurl));

        return assembleVdr(issuesByPurl, bomRefsByPurl);
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

                // Lowercase PURL coordinates for consistent cache keys and
                // correlation with Snyk responses, which lowercase PURLs.
                bomRefsByPurl
                        .computeIfAbsent(purl.getCoordinates().toLowerCase(), k -> new HashSet<>())
                        .add(component.getBomRef());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL '{}'; Skipping", component.getPurl(), e);
            }
        }

        return bomRefsByPurl;
    }

    private Map<String, List<SnykIssue>> analyzePurls(
            Collection<String> purls,
            Map<String, Set<String>> bomRefsByPurl) throws InterruptedException {
        if (purls.isEmpty()) {
            return Map.of();
        }

        final var issuesByPurl = new HashMap<String, List<SnykIssue>>(purls.size());

        for (final var purlBatch : (Iterable<List<String>>) () -> purls.stream()
                .gather(Gatherers.windowFixed(REQUEST_BATCH_SIZE))
                .iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            issuesByPurl.putAll(analyzePurlBatch(purlBatch, bomRefsByPurl));
        }

        return issuesByPurl;
    }

    private Map<String, List<SnykIssue>> analyzePurlBatch(
            Collection<String> purlBatch,
            Map<String, Set<String>> bomRefsByPurl) throws InterruptedException {
        if (purlBatch.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Fetching Snyk issues for {} PURLs", purlBatch.size());

        final SnykIssuesResponse response;
        try {
            response = fetchIssues(purlBatch);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to fetch Snyk issues", e);
        }

        final var issuesByPurl = new HashMap<String, List<SnykIssue>>(purlBatch.size());
        final var entriesToCache = new HashMap<String, byte @Nullable []>(purlBatch.size());

        if (response.data() != null) {
            for (final SnykIssue issue : response.data()) {
                final String issuePurl = SnykModelConverter.getIssuePurl(issue);
                if (issuePurl == null) {
                    LOGGER.warn("Unable to extract PURL from issue {}; Skipping", issue.id());
                    continue;
                }

                final String issuePurlLower = issuePurl.toLowerCase();
                if (!bomRefsByPurl.containsKey(issuePurlLower)) {
                    LOGGER.warn("Received issue {} for PURL '{}', but no component with this PURL was submitted", issue.id(), issuePurl);
                    continue;
                }

                issuesByPurl
                        .computeIfAbsent(issuePurlLower, k -> new ArrayList<>())
                        .add(issue);
            }
        }

        for (final var entry : issuesByPurl.entrySet()) {
            try {
                entriesToCache.put(entry.getKey(), objectMapper.writeValueAsBytes(entry.getValue()));
            } catch (IOException e) {
                LOGGER.warn("Failed to serialize issues for PURL '{}'; Skipping cache", entry.getKey(), e);
            }
        }

        for (final String purl : purlBatch) {
            if (!issuesByPurl.containsKey(purl)) {
                entriesToCache.put(purl, null);
            }
        }

        resultsCache.putMany(entriesToCache);
        return issuesByPurl;
    }

    private SnykIssuesResponse fetchIssues(Collection<String> purls) throws InterruptedException, IOException {
        if (purls.isEmpty()) {
            return new SnykIssuesResponse(List.of());
        }

        final String requestBody = """
                {"data":{"attributes":{"purls":%s}}}""".formatted(objectMapper.writeValueAsString(purls));

        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/rest/orgs/%s/packages/issues?version=%s".formatted(apiBaseUrl, orgId, apiVersion)))
                .header("Authorization", "token " + apiToken)
                .header("Content-Type", "application/vnd.api+json")
                .header("Accept", "application/vnd.api+json")
                .timeout(Duration.ofSeconds(30))
                .POST(BodyPublishers.ofString(requestBody))
                .build();

        final HttpResponse<InputStream> response = httpClient.send(request, BodyHandlers.ofInputStream());

        try (final InputStream bodyInputStream = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(bodyInputStream, SnykIssuesResponse.class);
            }

            throw new IOException("Snyk API request failed with status " + response.statusCode());
        }
    }

    private Bom assembleVdr(
            Map<String, List<SnykIssue>> issuesByPurl,
            Map<String, Set<String>> bomRefsByPurl) {
        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final var entry : issuesByPurl.entrySet()) {
            final String purl = entry.getKey();
            final List<SnykIssue> issues = entry.getValue();

            final Set<String> bomRefs = bomRefsByPurl.get(purl);
            if (bomRefs == null) {
                LOGGER.warn("""
                        Received vulnerabilities for PURL '{}', but no component \
                        with this PURL was submitted for analysis""", purl);
                continue;
            }

            for (final SnykIssue issue : issues) {
                final Vulnerability.Builder vulnBuilder =
                        vulnBuilderByVulnId.computeIfAbsent(
                                issue.id(),
                                _ -> SnykModelConverter.convert(issue, aliasSyncEnabled));

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

}
