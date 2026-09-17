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
import org.dependencytrack.vulnanalysis.api.RetryableVulnAnalysisException;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
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

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class SnykVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(SnykVulnAnalyzer.class);
    private static final int REQUEST_BATCH_SIZE = 100;
    private static final int CACHE_BATCH_SIZE = 500;
    private static final Set<String> SUPPORTED_PURL_TYPES = Set.of(
            "cargo",
            "cocoapods",
            "composer",
            "gem",
            "generic",
            "hex",
            "maven",
            "npm",
            "nuget",
            "pypi",
            "swift",
            "golang");

    private final Cache resultsCache;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiBaseUrl;
    private final String orgId;
    private final String apiToken;
    private final String apiVersion;
    private final boolean aliasSyncEnabled;
    private final boolean checksumMatchingEnabled;
    private final boolean batchRequestsEnabled;

    SnykVulnAnalyzer(
            Cache resultsCache,
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiBaseUrl,
            String orgId,
            String apiToken,
            String apiVersion,
            boolean aliasSyncEnabled,
            boolean checksumMatchingEnabled,
            boolean batchRequestsEnabled) {
        this.resultsCache = resultsCache;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiBaseUrl = apiBaseUrl;
        this.orgId = orgId;
        this.apiToken = apiToken;
        this.apiVersion = apiVersion;
        this.aliasSyncEnabled = aliasSyncEnabled;
        this.checksumMatchingEnabled = checksumMatchingEnabled;
        this.batchRequestsEnabled = batchRequestsEnabled;
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
                    if (issues.length > 0) {
                        issuesByPurl.put(purl, List.of(issues));
                    }
                } catch (IOException e) {
                    LOGGER.warn("Failed to deserialize cached issues for PURL '{}'; Will re-fetch", purl, e);
                    purlsToAnalyze.add(purl);
                }
            }
        }

        analyzePurls(purlsToAnalyze, bomRefsByPurl, issuesByPurl);

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
                    LOGGER.debug(
                            "Type '{}' of PURL '{}' is not supported; Skipping", purl.getType(), component.getPurl());
                    continue;
                }
                if (purl.getVersion() == null) {
                    LOGGER.debug("PURL '{}' has no version; Skipping", component.getPurl());
                    continue;
                }

                final String requestPurl = SnykPurlUtil.toSnykRequestPurl(purl, checksumMatchingEnabled);
                bomRefsByPurl.computeIfAbsent(requestPurl, _ -> new HashSet<>()).add(component.getBomRef());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Failed to parse PURL '{}'; Skipping", component.getPurl(), e);
            }
        }

        return bomRefsByPurl;
    }

    private void analyzePurls(
            Collection<String> purls, Map<String, Set<String>> bomRefsByPurl, Map<String, List<SnykIssue>> issuesByPurl)
            throws InterruptedException {
        if (purls.isEmpty()) {
            return;
        }

        for (final var purlBatch : (Iterable<List<String>>) () ->
                purls.stream().gather(Gatherers.windowFixed(REQUEST_BATCH_SIZE)).iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            analyzePurlBatch(purlBatch, bomRefsByPurl, issuesByPurl);
        }
    }

    private void analyzePurlBatch(
            Collection<String> purlBatch,
            Map<String, Set<String>> bomRefsByPurl,
            Map<String, List<SnykIssue>> issuesByPurl)
            throws InterruptedException {
        if (purlBatch.isEmpty()) {
            return;
        }

        LOGGER.debug("Fetching Snyk issues for {} PURLs", purlBatch.size());

        final var entriesToCache = new HashMap<String, byte @Nullable []>(purlBatch.size());
        try {
            if (batchRequestsEnabled) {
                final SnykIssuesResponse response = fetchIssues(purlBatch);
                logMetaErrors(response);
                applyBatchResponse(purlBatch, response, bomRefsByPurl, issuesByPurl, entriesToCache);
            } else {
                for (final String purl : purlBatch) {
                    if (Thread.interrupted()) {
                        throw new InterruptedException("Interrupted before all packages could be analyzed");
                    }

                    final SnykIssuesResponse response = fetchIssuesForPackage(purl);
                    logMetaErrors(response);
                    applyPerPackageResponse(purl, response, issuesByPurl, entriesToCache);
                }
            }
        } catch (IOException e) {
            final var message = "Failed to fetch Snyk issues";
            RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, message);
            throw new UncheckedIOException(message, e);
        }

        resultsCache.putMany(entriesToCache);
    }

    private void applyBatchResponse(
            Collection<String> purlBatch,
            SnykIssuesResponse response,
            Map<String, Set<String>> bomRefsByPurl,
            Map<String, List<SnykIssue>> issuesByPurl,
            Map<String, byte @Nullable []> entriesToCache) {
        final Map<String, SnykIssuesMeta.PackageMetaEntry> metaByNormalizedPurl = indexMetaPackages(response.meta());
        final Map<String, List<SnykIssue>> issuesByIssuePurl = indexIssuesByPurl(response.data());
        final boolean hasMetaErrors = hasMetaErrors(response.meta());

        for (final String requestPurl : purlBatch) {
            if (isChecksumQualifiedRequestPurl(requestPurl)) {
                processChecksumQualifiedPurl(
                        requestPurl,
                        metaByNormalizedPurl,
                        issuesByIssuePurl,
                        issuesByPurl,
                        entriesToCache,
                        hasMetaErrors);
            } else {
                processCoordinatesOnlyPurl(requestPurl, bomRefsByPurl, issuesByIssuePurl, issuesByPurl, entriesToCache);
            }
        }
    }

    /**
     * The per-package GET endpoint belongs to a single PURL. Issues in {@code data} are for that
     * package; match quality is reported as {@code meta.match} (not {@code meta.packages}).
     */
    private void applyPerPackageResponse(
            String requestPurl,
            SnykIssuesResponse response,
            Map<String, List<SnykIssue>> issuesByPurl,
            Map<String, byte @Nullable []> entriesToCache) {
        if (isChecksumQualifiedRequestPurl(requestPurl)) {
            final SnykIssuesMeta.Match match =
                    response.meta() != null ? response.meta().match() : null;
            if (match != null && match.type() != null) {
                applyChecksumMatch(requestPurl, match, issuesOf(response), issuesByPurl, entriesToCache);
                return;
            }
        }

        processDirectPackageIssues(requestPurl, issuesOf(response), issuesByPurl, entriesToCache);
    }

    private void processChecksumQualifiedPurl(
            String requestPurl,
            Map<String, SnykIssuesMeta.PackageMetaEntry> metaByNormalizedPurl,
            Map<String, List<SnykIssue>> issuesByIssuePurl,
            Map<String, List<SnykIssue>> issuesByRequestPurl,
            Map<String, byte @Nullable []> entriesToCache,
            boolean hasMetaErrors) {
        final String normalizedKey = SnykPurlUtil.normalizePurlKey(requestPurl);
        final SnykIssuesMeta.PackageMetaEntry metaEntry =
                normalizedKey != null ? metaByNormalizedPurl.get(normalizedKey) : null;

        if (metaEntry == null || metaEntry.match() == null || metaEntry.match().type() == null) {
            if (hasMetaErrors) {
                LOGGER.warn("""
                        No usable meta.packages entry for checksum-qualified PURL '{}' \
                        and meta.errors was non-empty; Skipping findings and negative-caching""", requestPurl);
                entriesToCache.put(requestPurl, null);
            } else {
                LOGGER.warn("""
                        No usable meta.packages entry for checksum-qualified PURL '{}'; \
                        Skipping findings and not caching""", requestPurl);
            }
            return;
        }

        final List<SnykIssue> issues = resolveIssuesForRequestPurl(requestPurl, metaEntry, issuesByIssuePurl);
        applyChecksumMatch(requestPurl, requireNonNull(metaEntry.match()), issues, issuesByRequestPurl, entriesToCache);
    }

    private void applyChecksumMatch(
            String requestPurl,
            SnykIssuesMeta.Match match,
            List<SnykIssue> issues,
            Map<String, List<SnykIssue>> issuesByRequestPurl,
            Map<String, byte @Nullable []> entriesToCache) {
        final SnykMatchType matchType = requireNonNull(match.type());
        switch (matchType) {
            case FULL, PARTIAL -> {
                if (matchType == SnykMatchType.PARTIAL) {
                    LOGGER.warn(
                            "Snyk match type partial for PURL '{}': {}; details={}",
                            requestPurl,
                            match.description(),
                            match.details());
                }
                if (!issues.isEmpty()) {
                    issuesByRequestPurl.put(requestPurl, issues);
                    cacheIssues(entriesToCache, requestPurl, issues);
                } else {
                    entriesToCache.put(requestPurl, null);
                }
            }
            case NONE -> {
                LOGGER.warn(
                        "Snyk match type none for PURL '{}': {}; details={}",
                        requestPurl,
                        match.description(),
                        match.details());
                entriesToCache.put(requestPurl, null);
            }
        }
    }

    private void processCoordinatesOnlyPurl(
            String requestPurl,
            Map<String, Set<String>> bomRefsByPurl,
            Map<String, List<SnykIssue>> issuesByIssuePurl,
            Map<String, List<SnykIssue>> issuesByRequestPurl,
            Map<String, byte @Nullable []> entriesToCache) {
        final List<SnykIssue> issues = new ArrayList<>();

        // Exact key match only. Do not strip qualifiers from issue PURLs to force a
        // coordinates match — that can attribute vulnerabilities across checksums.
        final List<SnykIssue> direct = issuesByIssuePurl.get(requestPurl);
        if (direct != null) {
            for (final SnykIssue issue : direct) {
                if (bomRefsByPurl.containsKey(requestPurl)) {
                    issues.add(issue);
                } else {
                    LOGGER.warn(
                            "Received issue {} for PURL '{}', but no component with this PURL was submitted",
                            issue.id(),
                            requestPurl);
                }
            }
        }

        processDirectPackageIssues(requestPurl, issues, issuesByRequestPurl, entriesToCache);
    }

    private void processDirectPackageIssues(
            String requestPurl,
            List<SnykIssue> issues,
            Map<String, List<SnykIssue>> issuesByRequestPurl,
            Map<String, byte @Nullable []> entriesToCache) {
        if (!issues.isEmpty()) {
            issuesByRequestPurl.put(requestPurl, issues);
            cacheIssues(entriesToCache, requestPurl, issues);
        } else {
            entriesToCache.put(requestPurl, null);
        }
    }

    private List<SnykIssue> resolveIssuesForRequestPurl(
            String requestPurl,
            SnykIssuesMeta.PackageMetaEntry metaEntry,
            Map<String, List<SnykIssue>> issuesByIssuePurl) {
        if (metaEntry.packageInfo() != null && metaEntry.packageInfo().url() != null) {
            final String packageUrl = metaEntry.packageInfo().url();
            final String packageKey = SnykPurlUtil.normalizePurlKey(packageUrl);
            if (packageKey != null) {
                final List<SnykIssue> byNormalized = issuesByIssuePurl.get(packageKey);
                if (byNormalized != null && !byNormalized.isEmpty()) {
                    return byNormalized;
                }
                final List<SnykIssue> byLower = issuesByIssuePurl.get(packageUrl.toLowerCase());
                if (byLower != null && !byLower.isEmpty()) {
                    return byLower;
                }
            }
        }

        final List<SnykIssue> direct = issuesByIssuePurl.get(requestPurl);
        if (direct != null && !direct.isEmpty()) {
            return direct;
        }

        final String normalizedRequest = SnykPurlUtil.normalizePurlKey(requestPurl);
        if (normalizedRequest != null) {
            final List<SnykIssue> byNormalizedRequest = issuesByIssuePurl.get(normalizedRequest);
            if (byNormalizedRequest != null && !byNormalizedRequest.isEmpty()) {
                return byNormalizedRequest;
            }
        }

        // Snyk often keys issues by coordinates-only PURLs even when the request was
        // checksum-qualified. Look up that exact coordinates key only — do not match other
        // checksum-qualified keys that share coordinates.
        final String requestCoords = coordinatesLower(requestPurl);
        if (requestCoords != null) {
            final List<SnykIssue> byCoords = issuesByIssuePurl.get(requestCoords);
            if (byCoords != null && !byCoords.isEmpty()) {
                return byCoords;
            }
        }

        return List.of();
    }

    private Map<String, List<SnykIssue>> indexIssuesByPurl(@Nullable List<SnykIssue> data) {
        final var issuesByIssuePurl = new HashMap<String, List<SnykIssue>>();
        if (data == null) {
            return issuesByIssuePurl;
        }

        for (final SnykIssue issue : data) {
            final String issuePurl = SnykModelConverter.getIssuePurl(issue);
            if (issuePurl == null) {
                LOGGER.warn("Unable to extract PURL from issue {}; Skipping", issue.id());
                continue;
            }

            final String lowerIssuePurl = issuePurl.toLowerCase();
            issuesByIssuePurl
                    .computeIfAbsent(lowerIssuePurl, _ -> new ArrayList<>())
                    .add(issue);
            final String normalizedIssuePurl = SnykPurlUtil.normalizePurlKey(issuePurl);
            if (normalizedIssuePurl != null && !normalizedIssuePurl.equals(lowerIssuePurl)) {
                issuesByIssuePurl
                        .computeIfAbsent(normalizedIssuePurl, _ -> new ArrayList<>())
                        .add(issue);
            }
        }

        return issuesByIssuePurl;
    }

    private static @Nullable String coordinatesLower(@Nullable String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        try {
            return new PackageURL(purl).getCoordinates().toLowerCase();
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    private boolean isChecksumQualifiedRequestPurl(String requestPurl) {
        if (!checksumMatchingEnabled) {
            return false;
        }
        try {
            return SnykPurlUtil.requiresChecksumMeta(new PackageURL(requestPurl), true);
        } catch (MalformedPackageURLException e) {
            return false;
        }
    }

    private Map<String, SnykIssuesMeta.PackageMetaEntry> indexMetaPackages(@Nullable SnykIssuesMeta meta) {
        final var indexed = new HashMap<String, SnykIssuesMeta.PackageMetaEntry>();
        if (meta == null || meta.packages() == null) {
            return indexed;
        }

        for (final var entry : meta.packages().entrySet()) {
            final String normalizedKey = SnykPurlUtil.normalizePurlKey(entry.getKey());
            if (normalizedKey != null) {
                indexed.put(normalizedKey, entry.getValue());
            }
            if (entry.getValue().match() != null
                    && entry.getValue().match().input() != null
                    && entry.getValue().match().input().purl() != null) {
                final String inputKey = SnykPurlUtil.normalizePurlKey(
                        entry.getValue().match().input().purl());
                if (inputKey != null) {
                    indexed.putIfAbsent(inputKey, entry.getValue());
                }
            }
        }
        return indexed;
    }

    private void cacheIssues(Map<String, byte @Nullable []> entriesToCache, String purl, List<SnykIssue> issues) {
        try {
            entriesToCache.put(purl, objectMapper.writeValueAsBytes(issues));
        } catch (IOException e) {
            LOGGER.warn("Failed to serialize issues for PURL '{}'; Skipping cache", purl, e);
        }
    }

    private static List<SnykIssue> issuesOf(SnykIssuesResponse response) {
        if (response.data() == null || response.data().isEmpty()) {
            return List.of();
        }
        return List.copyOf(response.data());
    }

    private static boolean hasMetaErrors(@Nullable SnykIssuesMeta meta) {
        return meta != null && meta.errors() != null && !meta.errors().isEmpty();
    }

    private static void logMetaErrors(SnykIssuesResponse response) {
        if (response.meta() == null || response.meta().errors() == null) {
            return;
        }
        for (final SnykIssuesMeta.Error error : response.meta().errors()) {
            LOGGER.warn("Snyk meta error: id={}, status={}, detail={}", error.id(), error.status(), error.detail());
        }
    }

    /**
     * Fetches issues one package at a time, using the endpoint Dependency-Track 4.x used.
     *
     * <p>Only used when the batch endpoint is not available to the organization.
     */
    private SnykIssuesResponse fetchIssuesForPackage(String purl) throws InterruptedException, IOException {
        final String encodedPurl = URLEncoder.encode(purl, StandardCharsets.UTF_8);

        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/rest/orgs/%s/packages/%s/issues?version=%s"
                        .formatted(apiBaseUrl, orgId, encodedPurl, apiVersion)))
                .header("Authorization", "token " + apiToken)
                .header("Accept", "application/vnd.api+json")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, BodyHandlers.ofInputStream());
        } catch (IOException e) {
            final var message = "Snyk API request failed";
            RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, message);
            throw new UncheckedIOException(message, e);
        }

        try (final InputStream bodyInputStream = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(bodyInputStream, SnykIssuesResponse.class);
            }

            // Snyk answers 404 for packages it does not know. The batch endpoint simply
            // omits them, so treat them as having no issues rather than failing the
            // analysis over a single unknown package.
            if (response.statusCode() == 404) {
                LOGGER.debug("Snyk does not know package '{}'", purl);
                return new SnykIssuesResponse(List.of());
            }

            RetryableVulnAnalysisException.throwIfRetryableHttpError(response);
            throw new IOException(
                    "Snyk API request for package '%s' failed with status %d".formatted(purl, response.statusCode()));
        }
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

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, BodyHandlers.ofInputStream());
        } catch (IOException e) {
            final var message = "Snyk API request failed";
            RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, message);
            throw new UncheckedIOException(message, e);
        }

        try (final InputStream bodyInputStream = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(bodyInputStream, SnykIssuesResponse.class);
            }

            RetryableVulnAnalysisException.throwIfRetryableHttpError(response);
            throw new IOException("Snyk API request failed with status " + response.statusCode());
        }
    }

    private Bom assembleVdr(Map<String, List<SnykIssue>> issuesByPurl, Map<String, Set<String>> bomRefsByPurl) {
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
                final Vulnerability.Builder vulnBuilder = vulnBuilderByVulnId.computeIfAbsent(
                        issue.id(), _ -> SnykModelConverter.convert(issue, aliasSyncEnabled));

                for (final String bomRef : bomRefs) {
                    vulnBuilder.addAffects(
                            VulnerabilityAffects.newBuilder().setRef(bomRef).build());
                }
            }
        }

        return Bom.newBuilder()
                .addAllVulnerabilities(vulnBuilderByVulnId.values().stream()
                        .map(Vulnerability.Builder::build)
                        .toList())
                .build();
    }
}
