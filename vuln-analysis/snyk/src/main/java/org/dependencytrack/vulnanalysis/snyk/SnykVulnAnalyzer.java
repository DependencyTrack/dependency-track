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

    SnykVulnAnalyzer(
            Cache resultsCache,
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiBaseUrl,
            String orgId,
            String apiToken,
            String apiVersion,
            boolean aliasSyncEnabled,
            boolean checksumMatchingEnabled) {
        this.resultsCache = resultsCache;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiBaseUrl = apiBaseUrl;
        this.orgId = orgId;
        this.apiToken = apiToken;
        this.apiVersion = apiVersion;
        this.aliasSyncEnabled = aliasSyncEnabled;
        this.checksumMatchingEnabled = checksumMatchingEnabled;
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

                final SnykCachedPurlResult cached = deserializeCachedResult(purl, cachedBytes);
                if (cached == null) {
                    // Corrupt entry — re-fetch.
                    purlsToAnalyze.add(purl);
                    continue;
                }

                applyCachedResult(purl, cached, issuesByPurl);
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

        final SnykIssuesResponse response;
        try {
            response = fetchIssues(purlBatch);
        } catch (IOException e) {
            final var message = "Failed to fetch Snyk issues";
            RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, message);
            throw new UncheckedIOException(message, e);
        }

        if (response.meta() != null && response.meta().errors() != null) {
            for (final SnykIssuesMeta.Error error : response.meta().errors()) {
                LOGGER.warn("Snyk meta error: id={}, status={}, detail={}", error.id(), error.status(), error.detail());
            }
        }

        final Map<String, SnykIssuesMeta.PackageMetaEntry> metaByNormalizedPurl = indexMetaPackages(response.meta());

        final var issuesByIssuePurl = new HashMap<String, List<SnykIssue>>();
        if (response.data() != null) {
            for (final SnykIssue issue : response.data()) {
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
        }

        final var entriesToCache = new HashMap<String, byte @Nullable []>(purlBatch.size());
        final boolean hasMetaErrors = response.meta() != null
                && response.meta().errors() != null
                && !response.meta().errors().isEmpty();

        for (final String requestPurl : purlBatch) {
            final boolean checksumPath = isChecksumQualifiedRequestPurl(requestPurl);
            if (checksumPath) {
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

        resultsCache.putMany(entriesToCache);
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
                // Permanent meta failure for this PURL (e.g. unsupported ecosystem): negative-cache.
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

        final SnykIssuesMeta.Match match = metaEntry.match();
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
                final List<SnykIssue> issues = resolveIssuesForRequestPurl(requestPurl, metaEntry, issuesByIssuePurl);
                if (!issues.isEmpty()) {
                    issuesByRequestPurl.put(requestPurl, issues);
                    putCachedResult(entriesToCache, requestPurl, SnykCachedPurlResult.of(matchType, issues, match));
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

        if (!issues.isEmpty()) {
            issuesByRequestPurl.put(requestPurl, issues);
            putCachedResult(entriesToCache, requestPurl, SnykCachedPurlResult.full(issues));
        } else {
            entriesToCache.put(requestPurl, null);
        }
    }

    private List<SnykIssue> resolveIssuesForRequestPurl(
            String requestPurl,
            SnykIssuesMeta.PackageMetaEntry metaEntry,
            Map<String, List<SnykIssue>> issuesByIssuePurl) {
        // Prefer correlating via package URL from meta.
        if (metaEntry.packageInfo() != null && metaEntry.packageInfo().url() != null) {
            final String packageUrl = metaEntry.packageInfo().url();
            final String packageKey = SnykPurlUtil.normalizePurlKey(packageUrl);
            if (packageKey != null) {
                final List<SnykIssue> byNormalized = issuesByIssuePurl.get(packageKey);
                if (byNormalized != null && !byNormalized.isEmpty()) {
                    return byNormalized;
                }
                // Issue map keys are lowercase raw strings; try lowercase package URL too.
                final List<SnykIssue> byLower = issuesByIssuePurl.get(packageUrl.toLowerCase());
                if (byLower != null && !byLower.isEmpty()) {
                    return byLower;
                }
            }
        }

        // Direct key match (issue PURL equals request PURL).
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
        // checksum-qualified keys that share coordinates (that would attribute issues for
        // checksum A onto a request with checksum B).
        final String requestCoords = coordinatesLower(requestPurl);
        if (requestCoords != null) {
            final List<SnykIssue> byCoords = issuesByIssuePurl.get(requestCoords);
            if (byCoords != null && !byCoords.isEmpty()) {
                return byCoords;
            }
        }

        return List.of();
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

    private void applyCachedResult(
            String requestPurl, SnykCachedPurlResult cached, Map<String, List<SnykIssue>> issuesByPurl) {
        // NONE outcomes are cached as null and never reach here as structured results.
        // FULL and PARTIAL with issues: attach cached findings.
        if (cached.issues() != null && !cached.issues().isEmpty()) {
            issuesByPurl.put(requestPurl, cached.issues());
        }
    }

    private boolean isChecksumQualifiedRequestPurl(String requestPurl) {
        if (!checksumMatchingEnabled) {
            return false;
        }
        try {
            return SnykPurlUtil.requiresChecksumMeta(new PackageURL(requestPurl), true);
        } catch (MalformedPackageURLException e) {
            // Request PURLs always come from SnykPurlUtil.toSnykRequestPurl and should
            // already be valid; do not substring-match "checksum=" (false positives).
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

    private void putCachedResult(
            Map<String, byte @Nullable []> entriesToCache, String purl, SnykCachedPurlResult result) {
        if (result.issues() == null || result.issues().isEmpty()) {
            entriesToCache.put(purl, null);
            return;
        }
        try {
            entriesToCache.put(purl, objectMapper.writeValueAsBytes(result));
        } catch (IOException e) {
            LOGGER.warn("Failed to serialize cached result for PURL '{}'; Skipping cache", purl, e);
        }
    }

    private @Nullable SnykCachedPurlResult deserializeCachedResult(String purl, byte @Nullable [] cachedBytes) {
        if (cachedBytes == null) {
            // Negative cache (FULL/PARTIAL empty, NONE, or meta-error permanent failure).
            return SnykCachedPurlResult.full(List.of());
        }

        try {
            return objectMapper.readValue(cachedBytes, SnykCachedPurlResult.class);
        } catch (IOException ignored) {
            // Fall through to legacy SnykIssue[] format.
        }

        try {
            final SnykIssue[] issues = objectMapper.readValue(cachedBytes, SnykIssue[].class);
            return SnykCachedPurlResult.full(List.of(issues));
        } catch (IOException e) {
            LOGGER.warn("Failed to deserialize cached issues for PURL '{}'; Will re-fetch", purl, e);
            return null;
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
