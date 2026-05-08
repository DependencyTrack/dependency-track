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
package org.dependencytrack.vulnanalysis.trivy;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import trivy.proto.cache.v1.BlobInfo;
import trivy.proto.cache.v1.DeleteBlobsRequest;
import trivy.proto.cache.v1.PutBlobRequest;
import trivy.proto.common.Application;
import trivy.proto.common.OS;
import trivy.proto.common.PackageInfo;
import trivy.proto.common.PkgIdentifier;
import trivy.proto.scanner.v1.Result;
import trivy.proto.scanner.v1.ScanOptions;
import trivy.proto.scanner.v1.ScanRequest;
import trivy.proto.scanner.v1.ScanResponse;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

final class TrivyVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyVulnAnalyzer.class);
    private static final String TOKEN_HEADER = "Trivy-Token";

    private final HttpClient httpClient;
    private final String apiBaseUrl;
    private final String apiToken;
    private final boolean ignoreUnfixed;
    private final boolean scanLibrary;
    private final boolean scanOs;

    TrivyVulnAnalyzer(
            HttpClient httpClient,
            String apiBaseUrl,
            String apiToken,
            boolean ignoreUnfixed,
            boolean scanLibrary,
            boolean scanOs) {
        this.httpClient = httpClient;
        this.apiBaseUrl = apiBaseUrl;
        this.apiToken = apiToken;
        this.ignoreUnfixed = ignoreUnfixed;
        this.scanLibrary = scanLibrary;
        this.scanOs = scanOs;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final var apps = new HashMap<String, Application.Builder>();
        final var pkgs = new HashMap<String, PackageInfo.Builder>();
        final var osMap = new HashMap<String, OS>();
        final var bomRefsByPurl = new HashMap<String, Set<String>>();

        for (final Component component : bom.getComponentsList()) {
            if (isInternalComponent(component)) {
                continue;
            }

            if (component.hasPurl() && component.hasBomRef()) {
                processComponentWithPurl(component, apps, pkgs, bomRefsByPurl);
            } else if (component.getType() == Classification.CLASSIFICATION_OPERATING_SYSTEM) {
                final String key = "%s-%s".formatted(component.getName(), component.getVersion());
                osMap.put(key, OS.newBuilder()
                        .setFamily(component.getName())
                        .setName(component.getVersion())
                        .build());
            }
        }

        final var blobs = new ArrayList<BlobInfo>();

        if (!apps.isEmpty()) {
            blobs.add(BlobInfo.newBuilder()
                    .setSchemaVersion(2)
                    .addAllApplications(apps.values().stream()
                            .map(Application.Builder::build)
                            .toList())
                    .build());
        }

        pkgs.forEach((key, value) -> {
            final BlobInfo.Builder builder = BlobInfo.newBuilder()
                    .setSchemaVersion(2)
                    .addPackageInfos(value);
            final OS os = osMap.get(key);
            if (os != null) {
                builder.setOs(os);
            }
            blobs.add(builder.build());
        });

        if (blobs.isEmpty()) {
            LOGGER.debug("No analyzable components found; Skipping analysis");
            return Bom.getDefaultInstance();
        }

        final var allResults = new ArrayList<Result>();
        for (final BlobInfo blob : blobs) {
            allResults.addAll(analyzeBlob(blob));
        }

        return assembleVdr(allResults, bomRefsByPurl);
    }

    private void processComponentWithPurl(
            Component component,
            Map<String, Application.Builder> apps,
            Map<String, PackageInfo.Builder> pkgs,
            Map<String, Set<String>> bomRefsByPurl) {

        final PackageURL purl;
        try {
            purl = new PackageURL(component.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to parse PURL '{}'; Skipping", component.getPurl(), e);
            return;
        }

        if (purl.getVersion() == null) {
            LOGGER.debug("Skipping component with PURL without version: {}", component.getPurl());
            return;
        }

        final String appType = PurlType.getAppType(purl.getType());
        if (PurlType.APP_TYPE_UNKNOWN.equals(appType)) {
            return;
        }

        String name = purl.getName();
        if (purl.getNamespace() != null) {
            if (PackageURL.StandardTypes.COMPOSER.equals(purl.getType())
                    || PackageURL.StandardTypes.GOLANG.equals(purl.getType())
                    || PackageURL.StandardTypes.NPM.equals(purl.getType())) {
                name = purl.getNamespace() + "/" + name;
            } else {
                name = purl.getNamespace() + ":" + name;
            }
        }

        bomRefsByPurl
                .computeIfAbsent(purl.toString(), ignored -> new HashSet<>())
                .add(component.getBomRef());

        if (!PurlType.APP_TYPE_PACKAGES.equals(appType)) {
            final Application.Builder app = apps.computeIfAbsent(appType, k -> Application.newBuilder().setType(k));
            app.addPackages(trivy.proto.common.Package.newBuilder()
                    .setName(name)
                    .setVersion(purl.getVersion())
                    .setSrcName(name)
                    .setSrcVersion(purl.getVersion())
                    .setIdentifier(PkgIdentifier.newBuilder().setPurl(purl.toString())));
        } else {
            processOsPackage(component, purl, pkgs);
        }
    }

    private void processOsPackage(
            Component component,
            PackageURL purl,
            Map<String, PackageInfo.Builder> pkgs) {

        String srcName = null;
        String srcVersion = null;
        String srcRelease = null;
        Integer srcEpoch = null;

        String pkgType = purl.getType();
        String arch = null;
        Integer epoch = null;

        if (purl.getQualifiers() != null) {
            arch = purl.getQualifiers().get("arch");

            final String tmpEpoch = purl.getQualifiers().get("epoch");
            if (tmpEpoch != null) {
                epoch = Integer.parseInt(tmpEpoch);
            }

            final String distro = purl.getQualifiers().get("distro");
            if (distro != null) {
                pkgType = URLDecoder.decode(distro, StandardCharsets.UTF_8);
            }
        }

        for (final Property property : component.getPropertiesList()) {
            final String propName = property.getName();
            final String propValue = property.getValue();

            if ("aquasecurity:trivy:SrcName".equals(propName)) {
                srcName = propValue;
            } else if ("aquasecurity:trivy:SrcVersion".equals(propName)) {
                srcVersion = propValue;
            } else if ("aquasecurity:trivy:SrcRelease".equals(propName)) {
                srcRelease = propValue;
            } else if ("aquasecurity:trivy:SrcEpoch".equals(propName)) {
                srcEpoch = Integer.parseInt(propValue);
            } else if (!pkgType.contains("-") && "aquasecurity:trivy:PkgType".equals(propName)) {
                pkgType = propValue;

                if (purl.getQualifiers() != null) {
                    final String distro = purl.getQualifiers().get("distro");
                    if (distro != null) {
                        pkgType += "-" + URLDecoder.decode(distro, StandardCharsets.UTF_8);
                    }
                }
            }
        }

        final PackageInfo.Builder pkg = pkgs.computeIfAbsent(pkgType, ignored -> PackageInfo.newBuilder());

        final trivy.proto.common.Package.Builder packageBuilder = trivy.proto.common.Package.newBuilder()
                .setName(purl.getName())
                .setVersion(purl.getVersion())
                .setArch(arch != null ? arch : "x86_64")
                .setSrcName(srcName != null ? srcName : purl.getName())
                .setSrcVersion(srcVersion != null ? srcVersion : purl.getVersion())
                .setIdentifier(PkgIdentifier.newBuilder().setPurl(purl.toString()));

        Optional.ofNullable(srcRelease).ifPresent(packageBuilder::setSrcRelease);
        Optional.ofNullable(epoch).ifPresent(packageBuilder::setEpoch);
        Optional.ofNullable(srcEpoch).ifPresent(packageBuilder::setSrcEpoch);

        pkg.addPackages(packageBuilder);
    }

    private List<Result> analyzeBlob(BlobInfo blobInfo) throws InterruptedException {
        final String diffId = "sha256:" + sha256Hex(UUID.randomUUID().toString());

        final PutBlobRequest putBlobRequest = PutBlobRequest.newBuilder()
                .setBlobInfo(blobInfo)
                .setDiffId(diffId)
                .build();

        try {
            putBlob(putBlobRequest);

            final ScanResponse response = scan(putBlobRequest);
            return response.getResultsList();
        } finally {
            try {
                deleteBlobs(putBlobRequest);
            } catch (Exception e) {
                LOGGER.warn("Failed to delete blob {}", diffId, e);
            }
        }
    }

    private void putBlob(PutBlobRequest request) throws InterruptedException {
        final byte[] responseBytes = sendProtobufRequest(
                "%s/twirp/trivy.cache.v1.Cache/PutBlob".formatted(apiBaseUrl),
                request.toByteArray());
        LOGGER.debug("PutBlob succeeded ({} bytes response)", responseBytes.length);
    }

    private ScanResponse scan(PutBlobRequest putBlobRequest) throws InterruptedException {
        final var scanOptionsBuilder = ScanOptions.newBuilder().addScanners("vuln");
        if (scanLibrary) {
            scanOptionsBuilder.addPkgTypes("library");
        }
        if (scanOs) {
            scanOptionsBuilder.addPkgTypes("os");
        }

        final var scanRequest = ScanRequest.newBuilder()
                .setTarget(putBlobRequest.getDiffId())
                .setArtifactId(putBlobRequest.getDiffId())
                .addBlobIds(putBlobRequest.getDiffId())
                .setOptions(scanOptionsBuilder)
                .build();

        final byte[] responseBytes = sendProtobufRequest(
                "%s/twirp/trivy.scanner.v1.Scanner/Scan".formatted(apiBaseUrl),
                scanRequest.toByteArray());

        try {
            return ScanResponse.parseFrom(responseBytes);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to parse scan response", e);
        }
    }

    private void deleteBlobs(PutBlobRequest putBlobRequest) throws InterruptedException {
        final var deleteRequest = DeleteBlobsRequest.newBuilder()
                .addBlobIds(putBlobRequest.getDiffId())
                .build();

        sendProtobufRequest(
                "%s/twirp/trivy.cache.v1.Cache/DeleteBlobs".formatted(apiBaseUrl),
                deleteRequest.toByteArray());
    }

    private byte[] sendProtobufRequest(String url, byte[] body) throws InterruptedException {
        final var request = HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .header("Accept", "application/protobuf")
                .header("Content-Type", "application/protobuf")
                .header(TOKEN_HEADER, apiToken)
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        final HttpResponse<byte[]> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException("Trivy API request to %s failed".formatted(url), e);
        }

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return response.body();
        }

        throw new IllegalStateException(
                "Trivy API request to %s failed with status %d".formatted(url, response.statusCode()));
    }

    private Bom assembleVdr(List<Result> results, Map<String, Set<String>> bomRefsByPurl) {
        final var vulnBuilderByVulnId = new HashMap<String, Vulnerability.Builder>();

        for (final Result result : results) {
            for (final trivy.proto.common.Vulnerability trivyVuln : result.getVulnerabilitiesList()) {
                if (ignoreUnfixed && trivyVuln.getStatus() != 3) {
                    continue;
                }

                final String purl = trivyVuln.getPkgIdentifier().getPurl();
                final Set<String> bomRefs = bomRefsByPurl.get(purl);
                if (bomRefs == null) {
                    LOGGER.warn(
                            "Vulnerability {} reported for PURL {}, but no matching component; Skipping",
                            trivyVuln.getVulnerabilityId(), purl);
                    continue;
                }

                final Vulnerability.Builder vulnBuilder =
                        vulnBuilderByVulnId.computeIfAbsent(
                                trivyVuln.getVulnerabilityId(),
                                ignored -> TrivyModelConverter.convert(trivyVuln));

                for (final String bomRef : bomRefs) {
                    vulnBuilder.addAffects(
                            VulnerabilityAffects.newBuilder()
                                    .setRef(bomRef)
                                    .build());
                }
            }
        }

        if (vulnBuilderByVulnId.isEmpty()) {
            return Bom.getDefaultInstance();
        }

        return Bom.newBuilder()
                .addAllVulnerabilities(
                        vulnBuilderByVulnId.values().stream()
                                .map(Vulnerability.Builder::build)
                                .toList())
                .build();
    }

    private static boolean isInternalComponent(Component component) {
        return component.getPropertiesList().stream().anyMatch(
                property -> "dependencytrack:internal:is-internal-component".equalsIgnoreCase(property.getName()));
    }

    private static String sha256Hex(String input) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
