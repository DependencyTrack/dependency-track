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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import trivy.proto.cache.v1.PutBlobRequest;
import trivy.proto.common.CVSS;
import trivy.proto.common.DataSource;
import trivy.proto.common.PkgIdentifier;
import trivy.proto.scanner.v1.Result;
import trivy.proto.scanner.v1.ScanResponse;

import java.net.http.HttpClient;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cyclonedx.proto.v1_7.Classification.CLASSIFICATION_LIBRARY;

@WireMockTest
class TrivyVulnAnalyzerTest {

    private TrivyVulnAnalyzer analyzer;

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        analyzer = new TrivyVulnAnalyzer(
                HttpClient.newHttpClient(),
                wmRuntimeInfo.getHttpBaseUrl(),
                "token",
                false,
                true,
                false);
    }

    @Test
    void testAnalyzeWithVulnerabilities() throws Exception {
        stubTrivyEndpoints(buildScanResponseWithVulnerability());

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("woodstox-core")
                        .setGroup("com.fasterxml.woodstox")
                        .setVersion("5.0.0")
                        .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThatJson(JsonFormat.printer().print(vdr)).isEqualTo(/* language=JSON */ """
                {
                  "vulnerabilities": [
                    {
                      "id": "CVE-2022-40152",
                      "source": {
                        "name": "NVD"
                      },
                      "ratings": [
                        {
                          "source": {
                            "name": "ghsa"
                          },
                          "score": 6.5,
                          "method": "SCORE_METHOD_CVSSV31",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
                        },
                        {
                          "source": {
                            "name": "ghsa"
                          },
                          "score": 7.1,
                          "method": "SCORE_METHOD_CVSSV4",
                          "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
                        },
                        {
                          "severity": "SEVERITY_MEDIUM"
                        }
                      ],
                      "cwes": [
                        787,
                        121
                      ],
                      "description": "Those using Woodstox to parse XML data may be vulnerable to Denial of Service attacks (DOS) if DTD support is enabled. If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow. This effect may support a denial of service attack.",
                      "advisories": [
                        {
                          "url": "https://access.redhat.com/security/cve/CVE-2022-40152"
                        },
                        {
                          "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47434"
                        }
                      ],
                      "created": "2022-09-16T10:15:09.877Z",
                      "published": "2022-09-16T10:15:09.877Z",
                      "updated": "2023-02-09T01:36:03.637Z",
                      "affects": [
                        {
                          "ref": "1"
                        }
                      ],
                      "properties": [
                        {
                          "name": "dependency-track:vuln:title",
                          "value": "woodstox-core: woodstox to serialise XML data was vulnerable to Denial of Service attacks"
                        },
                        {
                          "name": "dependency-track:vuln:patched-versions",
                          "value": "6.4.0, 5.4.0"
                        }
                      ]
                    }
                  ]
                }
                """);

        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Accept", equalTo("application/protobuf"))
                .withHeader("Content-Type", equalTo("application/protobuf")));
        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs")));
    }

    @Test
    void testAnalyzeWithNoVulnerabilities() throws Exception {
        stubTrivyEndpoints(ScanResponse.newBuilder()
                .addResults(Result.newBuilder()
                        .setClass_("lang-pkgs")
                        .setTarget("java")
                        .setType("jar")
                        .build())
                .build());

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("woodstox-core")
                        .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob")));
        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs")));
    }

    @Test
    void testAnalyzeWithConnectionError() {
        stubFor(any(anyUrl())
                .willReturn(aResponse()
                        .withFault(CONNECTION_RESET_BY_PEER)));

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("woodstox-core")
                        .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        assertThatThrownBy(() -> analyzer.analyze(bom))
                .hasMessageContaining("Trivy API request");

        verify(exactly(1), postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob")));
        verify(exactly(0), postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
    }

    @Test
    void testAnalyzeRespectsConfiguredScanningOption() throws Exception {
        stubTrivyEndpoints(ScanResponse.newBuilder()
                .addResults(Result.newBuilder()
                        .setClass_("lang-pkgs")
                        .setTarget("java")
                        .setType("jar")
                        .build())
                .build());

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("woodstox-core")
                        .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        analyzer.analyze(bom);

        verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
        final var requests = WireMock.findAll(
                postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
        final var scanRequest = trivy.proto.scanner.v1.ScanRequest.parseFrom(requests.get(0).getBody());

        assertThat(scanRequest.getOptions().getPkgTypesCount()).isEqualTo(1);
        assertThat(scanRequest.getOptions().getPkgTypes(0)).isEqualTo("library");
    }

    @Test
    void testIsCapableFiltersCorrectly() throws Exception {
        stubTrivyEndpoints(ScanResponse.newBuilder()
                .addResults(Result.newBuilder()
                        .setClass_("lang-pkgs")
                        .setTarget("java")
                        .setType("jar")
                        .build())
                .build());

        // Components without bomRef or without PURL (and not OS) are skipped.
        // Unsupported PURL types are skipped.
        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("woodstox-core")
                        .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("2")
                        .setName("unknown-thing")
                        .setPurl("pkg:xxx/something@1.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .addComponents(Component.newBuilder()
                        .setName("no-bomref")
                        .setPurl("pkg:maven/foo/bar@1.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("4")
                        .setName("ubuntu")
                        .setVersion("22.04")
                        .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        // Only one PutBlob call for the one valid component (maven).
        verify(exactly(1), postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob")));
    }

    @Test
    void testSkipsInternalComponents() throws Exception {
        stubTrivyEndpoints(ScanResponse.getDefaultInstance());

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("internal-lib")
                        .setPurl("pkg:maven/com.acme/internal-lib@1.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .addProperties(Property.newBuilder()
                                .setName("dependencytrack:internal:is-internal-component")
                                .setValue("true")
                                .build())
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(exactly(0), postRequestedFor(anyUrl()));
    }

    @Test
    void testAnalyzeIgnoresUnfixedWhenConfigured(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final var ignoreUnfixedAnalyzer = new TrivyVulnAnalyzer(
                HttpClient.newHttpClient(),
                wmRuntimeInfo.getHttpBaseUrl(),
                "token",
                true,  // ignoreUnfixed
                true,
                false);

        // Build a response with one fixed (status=3) and one unfixed (status=0) vulnerability.
        final ScanResponse scanResponse = ScanResponse.newBuilder()
                .addResults(Result.newBuilder()
                        .setClass_("lang-pkgs")
                        .setTarget("java")
                        .setType("jar")
                        .addVulnerabilities(trivy.proto.common.Vulnerability.newBuilder()
                                .setStatus(3)
                                .setVulnerabilityId("CVE-2022-11111")
                                .setPkgIdentifier(PkgIdentifier.newBuilder()
                                        .setPurl("pkg:maven/com.example/lib@1.0.0"))
                                .setFixedVersion("2.0.0")
                                .setSeverity(trivy.proto.common.Severity.HIGH)
                                .build())
                        .addVulnerabilities(trivy.proto.common.Vulnerability.newBuilder()
                                .setStatus(0)
                                .setVulnerabilityId("CVE-2022-22222")
                                .setPkgIdentifier(PkgIdentifier.newBuilder()
                                        .setPurl("pkg:maven/com.example/lib@1.0.0"))
                                .setSeverity(trivy.proto.common.Severity.MEDIUM)
                                .build())
                        .build())
                .build();

        stubTrivyEndpoints(scanResponse);

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("lib")
                        .setPurl("pkg:maven/com.example/lib@1.0.0")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = ignoreUnfixedAnalyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
        assertThat(vdr.getVulnerabilities(0).getId()).isEqualTo("CVE-2022-11111");
    }

    @Test
    void testAnalyzeOsPackageWithProperties() throws Exception {
        // Simulate Trivy returning a vulnerability for an OS package.
        final ScanResponse scanResponse = ScanResponse.newBuilder()
                .addResults(Result.newBuilder()
                        .setClass_("os-pkgs")
                        .setTarget("ubuntu 22.04")
                        .setType("ubuntu")
                        .addVulnerabilities(trivy.proto.common.Vulnerability.newBuilder()
                                .setStatus(3)
                                .setVulnerabilityId("CVE-2023-99999")
                                .setPkgIdentifier(PkgIdentifier.newBuilder()
                                        .setPurl("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4?arch=amd64&distro=ubuntu-22.04"))
                                .setSeverity(trivy.proto.common.Severity.HIGH)
                                .build())
                        .build())
                .build();

        stubTrivyEndpoints(scanResponse);

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("os-1")
                        .setName("ubuntu")
                        .setVersion("22.04")
                        .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
                        .build())
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("libc6")
                        .setVersion("2.35-0ubuntu3.4")
                        .setPurl("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4?arch=amd64&distro=ubuntu-22.04")
                        .setType(CLASSIFICATION_LIBRARY)
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcName").setValue("glibc").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcVersion").setValue("2.35").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:SrcRelease").setValue("0ubuntu3.4").build())
                        .addProperties(Property.newBuilder()
                                .setName("aquasecurity:trivy:PkgType").setValue("ubuntu").build())
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr.getVulnerabilitiesList()).hasSize(1);
        assertThat(vdr.getVulnerabilities(0).getId()).isEqualTo("CVE-2023-99999");
        assertThat(vdr.getVulnerabilities(0).getAffects(0).getRef()).isEqualTo("1");
    }

    @Test
    void testSkipsComponentsWithoutVersion() throws Exception {
        stubTrivyEndpoints(ScanResponse.getDefaultInstance());

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setName("some-lib")
                        .setPurl("pkg:maven/com.example/some-lib")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        // No Trivy API calls should be made.
        verify(exactly(0), postRequestedFor(anyUrl()));
    }

    @Test
    void testAnalyzeComposerComponentUsesSlashSeparator() throws Exception {
        stubTrivyEndpoints(ScanResponse.getDefaultInstance());

        final Bom bom = Bom.newBuilder()
                .addComponents(Component.newBuilder()
                        .setBomRef("1")
                        .setGroup("symfony")
                        .setName("http-foundation")
                        .setVersion("6.4.15")
                        .setPurl("pkg:composer/symfony/http-foundation@6.4.15")
                        .setType(CLASSIFICATION_LIBRARY)
                        .build())
                .build();

        analyzer.analyze(bom);

        // The PutBlob request body carries the composer coordinate sent to
        // Trivy. Packagist indexes composer packages as "vendor/package"
        // (slash), so DT must transmit "symfony/http-foundation" rather than
        // "symfony:http-foundation" for the Trivy server to match.
        final var putBlobRequests = WireMock.findAll(
                postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob")));
        assertThat(putBlobRequests).hasSize(1);

        final PutBlobRequest putBlobRequest = PutBlobRequest.parseFrom(putBlobRequests.get(0).getBody());
        assertThat(putBlobRequest.getBlobInfo().getApplicationsList())
                .anySatisfy(app -> assertThat(app.getPackagesList())
                        .anySatisfy(pkg -> assertThat(pkg.getName())
                                .isEqualTo("symfony/http-foundation")));
    }

    private void stubTrivyEndpoints(ScanResponse scanResponse) {
        stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")));

        stubFor(post(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")
                        .withBody(scanResponse.toByteArray())));

        stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")));
    }

    private static ScanResponse buildScanResponseWithVulnerability() {
        try {
            return ScanResponse.newBuilder()
                    .addResults(Result.newBuilder()
                            .setClass_("lang-pkgs")
                            .setTarget("java")
                            .setType("jar")
                            .addVulnerabilities(trivy.proto.common.Vulnerability.newBuilder()
                                    .setStatus(3)
                                    .setVulnerabilityId("CVE-2022-40152")
                                    .setPkgName("com.fasterxml.woodstox:woodstox-core")
                                    .setPkgIdentifier(PkgIdentifier.newBuilder()
                                            .setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz")
                                            .build())
                                    .setInstalledVersion("5.0.0")
                                    .setFixedVersion("6.4.0, 5.4.0")
                                    .setTitle("woodstox-core: woodstox to serialise XML data was vulnerable to Denial of Service attacks")
                                    .setDescription(
                                            "Those using Woodstox to parse XML data may be vulnerable to "
                                                    + "Denial of Service attacks (DOS) if DTD support is enabled. "
                                                    + "If the parser is running on user supplied input, an attacker "
                                                    + "may supply content that causes the parser to crash by stackoverflow. "
                                                    + "This effect may support a denial of service attack.")
                                    .setPublishedDate(Timestamps.parse("2022-09-16T10:15:09.877Z"))
                                    .setLastModifiedDate(Timestamps.parse("2023-02-09T01:36:03.637Z"))
                                    .setSeverity(trivy.proto.common.Severity.MEDIUM)
                                    .setSeveritySource("ghsa")
                                    .putAllCvss(Map.ofEntries(
                                            Map.entry("ghsa", CVSS.newBuilder()
                                                    .setV3Vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")
                                                    .setV3Score(6.5)
                                                    .setV40Vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N")
                                                    .setV40Score(7.1)
                                                    .build()),
                                            Map.entry("nvd", CVSS.newBuilder()
                                                    .setV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
                                                    .setV3Score(7.5)
                                                    .build())
                                    ))
                                    .addAllCweIds(List.of("CWE-787", "CWE-121"))
                                    .addAllReferences(List.of(
                                            "https://access.redhat.com/security/cve/CVE-2022-40152",
                                            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47434"))
                                    .setDataSource(DataSource.newBuilder()
                                            .setId("ghsa")
                                            .setName("GitHub Security Advisory Maven")
                                            .setUrl("https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven")
                                            .build())
                                    .build())
                            .build())
                    .build();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

}
