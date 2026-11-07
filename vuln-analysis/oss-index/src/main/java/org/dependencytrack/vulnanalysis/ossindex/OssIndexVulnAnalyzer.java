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
import io.github.nscuro.versatile.VersionFactory;
import io.github.nscuro.versatile.version.KnownVersioningSchemes;
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
import java.util.Objects;
import java.util.Set;
import java.util.stream.Gatherers;

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
            "cargo",
            "cocoapods",
            "composer",
            "conan",
            "conda",
            "cran",
            "gem",
            "golang",
            "maven",
            "npm",
            "nuget",
            "pypi",
            "rpm",
            "swift");

    private final Cache resultsCache;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String apiUrl;
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
        this.apiUrl = apiUrl.toString().replaceAll("/+$", "");
        if (username != null && apiToken != null) {
            final String basicAuthCredentials = Base64.getEncoder()
                    .encodeToString("%s:%s".formatted(username, apiToken).getBytes(StandardCharsets.UTF_8));
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
                    LOGGER.debug(
                            "Type '{}' of PURL '{}' is not supported; Skipping", purl.getType(), component.getPurl());
                    continue;
                }
                if (purl.getVersion() == null) {
                    LOGGER.debug("PURL '{}' has no version; Skipping", component.getPurl());
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

    private Map<String, List<ComponentReportVulnerability>> analyzePurls(Collection<String> purls)
            throws InterruptedException {
        if (purls.isEmpty()) {
            return Map.of();
        }

        final var reportedVulnsByPurl = new HashMap<String, List<ComponentReportVulnerability>>(purls.size());

        for (final var purlBatch : (Iterable<List<String>>) () ->
                purls.stream().gather(Gatherers.windowFixed(REQUEST_BATCH_SIZE)).iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            reportedVulnsByPurl.putAll(analyzePurlBatch(purlBatch));
        }

        return reportedVulnsByPurl;
    }

    private Map<String, List<ComponentReportVulnerability>> analyzePurlBatch(Collection<String> purlBatch)
            throws InterruptedException {
        if (purlBatch.isEmpty()) {
            return Map.of();
        }

        LOGGER.debug("Fetching component reports for {} PURLs", purlBatch.size());

        final List<ComponentReport> batchReports;
        try {
            batchReports = getComponentReports(purlBatch);
        } catch (IOException e) {
            RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, "Failed to retrieve component report");
            throw new UncheckedIOException("Failed to retrieve component report", e);
        }

        final var reportBySubmittedPurl = new HashMap<String, ComponentReport>();
        final var reportsByExactCoord = new HashMap<String, ComponentReport>();
        for (final ComponentReport report : batchReports) {
            if (report.coordinates() != null) {
                reportsByExactCoord.put(report.coordinates(), report);
            }
        }

        final var unmatchedSubmittedPurls = new ArrayList<String>();
        for (final String purl : purlBatch) {
            final ComponentReport exactMatch = reportsByExactCoord.get(purl);
            if (exactMatch != null) {
                reportBySubmittedPurl.put(purl, exactMatch);
            } else {
                unmatchedSubmittedPurls.add(purl);
            }
        }

        if (!unmatchedSubmittedPurls.isEmpty()) {
            for (final String submittedPurl : unmatchedSubmittedPurls) {
                final PackageURL parsedSubmitted = parsePurlQuietly(submittedPurl);
                if (parsedSubmitted == null) {
                    continue;
                }

                for (final ComponentReport report : batchReports) {
                    if (report.coordinates() == null) {
                        continue;
                    }
                    final PackageURL parsedReport = parsePurlQuietly(report.coordinates());
                    if (parsedReport != null && arePurlsEquivalent(parsedSubmitted, parsedReport)) {
                        reportBySubmittedPurl.put(submittedPurl, report);
                        LOGGER.debug(
                                "Correlated OSS Index report coordinates '{}' to submitted PURL '{}'",
                                report.coordinates(),
                                submittedPurl);
                        break;
                    }
                }
            }
        }

        final var reportedVulnsByPurl = new HashMap<String, List<ComponentReportVulnerability>>(batchReports.size());
        final var entriesToCache = new HashMap<String, byte @Nullable []>(purlBatch.size());

        for (final var entry : reportBySubmittedPurl.entrySet()) {
            final String submittedPurl = entry.getKey();
            final ComponentReport report = entry.getValue();

            if (report.vulnerabilities() != null && !report.vulnerabilities().isEmpty()) {
                reportedVulnsByPurl.put(submittedPurl, report.vulnerabilities());
                try {
                    final byte[] serializedBytes = objectMapper.writeValueAsBytes(report.vulnerabilities());
                    entriesToCache.put(submittedPurl, serializedBytes);
                    if (report.coordinates() != null && !report.coordinates().equals(submittedPurl)) {
                        entriesToCache.put(report.coordinates(), serializedBytes);
                    }
                } catch (IOException e) {
                    LOGGER.warn("Failed to serialize component report for PURL '{}'; Skipping cache", submittedPurl, e);
                }
            } else {
                entriesToCache.put(submittedPurl, null);
                if (report.coordinates() != null && !report.coordinates().equals(submittedPurl)) {
                    entriesToCache.put(report.coordinates(), null);
                }
            }
        }

        for (final String purl : purlBatch) {
            if (!reportBySubmittedPurl.containsKey(purl)) {
                entriesToCache.put(purl, null);
            }
        }

        for (final ComponentReport report : batchReports) {
            if (report.coordinates() != null && !entriesToCache.containsKey(report.coordinates())) {
                if (report.vulnerabilities() != null
                        && !report.vulnerabilities().isEmpty()) {
                    reportedVulnsByPurl.put(report.coordinates(), report.vulnerabilities());
                    try {
                        entriesToCache.put(
                                report.coordinates(), objectMapper.writeValueAsBytes(report.vulnerabilities()));
                    } catch (IOException e) {
                        LOGGER.warn(
                                "Failed to serialize component report for PURL '{}'; Skipping cache",
                                report.coordinates(),
                                e);
                    }
                } else {
                    entriesToCache.put(report.coordinates(), null);
                }
            }
        }

        resultsCache.putMany(entriesToCache);
        return reportedVulnsByPurl;
    }

    private static @Nullable PackageURL parsePurlQuietly(final String coordinates) {
        try {
            return new PackageURL(coordinates);
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    private static boolean arePurlsEquivalent(final PackageURL purl1, final PackageURL purl2) {
        if (!Objects.equals(purl1.getType(), purl2.getType())
                || !areNamespacesEqual(purl1.getNamespace(), purl2.getNamespace())
                || !Objects.equals(purl1.getName(), purl2.getName())
                || !areSubpathsEqual(purl1.getSubpath(), purl2.getSubpath())
                || !areQualifiersEqual(purl1.getQualifiers(), purl2.getQualifiers())) {
            return false;
        }

        if (Objects.equals(purl1.getVersion(), purl2.getVersion())) {
            return true;
        }

        final String scheme = KnownVersioningSchemes.fromPurlType(purl1.getType())
                .orElse(
                        PackageURL.StandardTypes.GOLANG.equals(purl1.getType())
                                ? KnownVersioningSchemes.SCHEME_GOLANG
                                : null);
        if (scheme != null && purl1.getVersion() != null && purl2.getVersion() != null) {
            try {
                final var v1 = VersionFactory.forScheme(scheme, purl1.getVersion());
                final var v2 = VersionFactory.forScheme(scheme, purl2.getVersion());
                return v1.compareTo(v2) == 0;
            } catch (Exception e) {
                LOGGER.debug(
                        "Failed to compare versions '{}' and '{}' for scheme '{}'",
                        purl1.getVersion(),
                        purl2.getVersion(),
                        scheme,
                        e);
                return false;
            }
        }

        return false;
    }

    private static boolean areNamespacesEqual(final @Nullable String n1, final @Nullable String n2) {
        final String s1 = (n1 == null || n1.isEmpty()) ? null : n1;
        final String s2 = (n2 == null || n2.isEmpty()) ? null : n2;
        return Objects.equals(s1, s2);
    }

    private static boolean areSubpathsEqual(final @Nullable String s1, final @Nullable String s2) {
        final String n1 = (s1 == null || s1.isEmpty()) ? null : s1;
        final String n2 = (s2 == null || s2.isEmpty()) ? null : s2;
        return Objects.equals(n1, n2);
    }

    private static boolean areQualifiersEqual(
            final @Nullable Map<String, String> q1, final @Nullable Map<String, String> q2) {
        if ((q1 == null || q1.isEmpty()) && (q2 == null || q2.isEmpty())) {
            return true;
        }
        return Objects.equals(q1, q2);
    }

    private List<ComponentReport> getComponentReports(Collection<String> coordinates)
            throws InterruptedException, IOException {
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

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, BodyHandlers.ofInputStream());
        } catch (IOException e) {
            RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, "OSS Index API request failed");
            throw new UncheckedIOException("OSS Index API request failed", e);
        }

        try (final InputStream bodyInputStream = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(bodyInputStream, COMPONENT_REPORTS_TYPE);
            }

            RetryableVulnAnalysisException.throwIfRetryableHttpError(response);
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
                final Vulnerability.Builder vulnBuilder = vulnBuilderByVulnId.computeIfAbsent(
                        reportedVuln.id(), _ -> OssIndexModelConverter.convert(reportedVuln, aliasSyncEnabled));

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
