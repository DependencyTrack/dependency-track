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
package org.dependencytrack.tasks.scanners;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import alpine.security.crypto.DataEncryption;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.protobuf.util.Timestamps;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.TrivyAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import trivy.proto.common.CVSS;
import trivy.proto.common.DataSource;
import trivy.proto.common.PkgIdentifier;
import trivy.proto.scanner.v1.Result;
import trivy.proto.scanner.v1.ScanResponse;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_IGNORE_UNFIXED;

public class TrivyAnalysisTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    @BeforeClass
    public static void setUpClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(
                SCANNER_TRIVY_ENABLED.getGroupName(),
                SCANNER_TRIVY_ENABLED.getPropertyName(),
                "true",
                SCANNER_TRIVY_ENABLED.getPropertyType(),
                SCANNER_TRIVY_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_TRIVY_API_TOKEN.getGroupName(),
                SCANNER_TRIVY_API_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("token"),
                SCANNER_TRIVY_API_TOKEN.getPropertyType(),
                SCANNER_TRIVY_API_TOKEN.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_TRIVY_BASE_URL.getGroupName(),
                SCANNER_TRIVY_BASE_URL.getPropertyName(),
                wireMock.baseUrl(),
                SCANNER_TRIVY_BASE_URL.getPropertyType(),
                SCANNER_TRIVY_BASE_URL.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_TRIVY_IGNORE_UNFIXED.getGroupName(),
                SCANNER_TRIVY_IGNORE_UNFIXED.getPropertyName(),
                "false",
                SCANNER_TRIVY_IGNORE_UNFIXED.getPropertyType(),
                SCANNER_TRIVY_IGNORE_UNFIXED.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getDefaultPropertyValue(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyType(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getDescription()
        );
    }

    @After
    public void tearDown() {
        NOTIFICATIONS.clear();
    }

    @AfterClass
    public static void tearDownClass() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
    }

    @Test
    public void testIsCapable() {
        final var asserts = new SoftAssertions();

        for (final Map.Entry<String, Boolean> test : Map.of(
                "pkg:maven/com.fasterxml.woodstox/woodstox-core", false, // Missing version
                "pkg:xxx/github.com/CycloneDX/cyclonedx-go@0.7.0", false, // Unsupported type
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", true,
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz", true
        ).entrySet()) {
            final var component = new Component();
            component.setPurl(test.getKey());
            asserts.assertThat(new TrivyAnalysisTask().isCapable(component)).isEqualTo(test.getValue());
        }

        asserts.assertAll();
    }

    @Test
    public void testAnalyzeWithRetry() throws ParseException {
        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .inScenario("scanRequestWithGatewayTimeout")
                .willReturn(aResponse()
                        .withStatus(504))
                .willSetStateTo("secondAttempt"));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .inScenario("scanRequestWithGatewayTimeout")
                .whenScenarioStateIs("secondAttempt")
                .willReturn(aResponse()
                        .withStatus(504))
                .willSetStateTo("thirdAttempt"));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .inScenario("scanRequestWithGatewayTimeout")
                .whenScenarioStateIs("thirdAttempt")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")
                        .withBody(ScanResponse.newBuilder()
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
                                                .setDescription("""
                                                        Those using Woodstox to parse XML data may be vulnerable to \
                                                        Denial of Service attacks (DOS) if DTD support is enabled. \
                                                        If the parser is running on user supplied input, an attacker \
                                                        may supply content that causes the parser to crash by stackoverflow. \
                                                        This effect may support a denial of service attack.""")
                                                .setPublishedDate(Timestamps.parse("2022-09-16T10:15:09.877Z"))
                                                .setLastModifiedDate(Timestamps.parse("2023-02-09T01:36:03.637Z"))
                                                .setSeverity(trivy.proto.common.Severity.MEDIUM)
                                                .setSeveritySource("ghsa")
                                                .putAllVendorSeverity(Map.ofEntries(
                                                        Map.entry("amazon", trivy.proto.common.Severity.MEDIUM),
                                                        Map.entry("ghsa", trivy.proto.common.Severity.MEDIUM),
                                                        Map.entry("nvd", trivy.proto.common.Severity.HIGH),
                                                        Map.entry("redhat", trivy.proto.common.Severity.MEDIUM)
                                                ))
                                                .putAllCvss(Map.ofEntries(
                                                        Map.entry("ghsa", CVSS.newBuilder()
                                                                .setV3Vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")
                                                                .setV3Score(6.5)
                                                                .build()),
                                                        Map.entry("nvd", CVSS.newBuilder()
                                                                .setV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
                                                                .setV3Score(7.5)
                                                                .build()),
                                                        Map.entry("redhat", CVSS.newBuilder()
                                                                .setV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
                                                                .setV3Score(7.5)
                                                                .build())
                                                ))
                                                .addAllCweIds(List.of("CWE-787", "CWE-121"))
                                                .addAllReferences(List.of(
                                                        "https://access.redhat.com/security/cve/CVE-2022-40152",
                                                        "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47434",
                                                        "https://github.com/FasterXML/woodstox",
                                                        "https://github.com/FasterXML/woodstox/issues/157",
                                                        "https://github.com/FasterXML/woodstox/issues/160",
                                                        "https://github.com/FasterXML/woodstox/pull/159",
                                                        "https://github.com/advisories/GHSA-3f7h-mf4q-vrm4",
                                                        "https://github.com/x-stream/xstream/issues/304",
                                                        "https://nvd.nist.gov/vuln/detail/CVE-2022-40152",
                                                        "https://www.cve.org/CVERecord?id=CVE-2022-40152"
                                                ))
                                                .setDataSource(DataSource.newBuilder()
                                                        .setId("ghsa")
                                                        .setName("GitHub Security Advisory Maven")
                                                        .setUrl("https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven")
                                                        .build())
                                                .build())
                                        .build())
                                .build()
                                .toByteArray())));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).satisfiesExactly(vuln -> {
            assertThat(vuln.getVulnId()).isEqualTo("CVE-2022-40152");
            assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
            assertThat(vuln.getTitle()).isEqualTo("woodstox-core: woodstox to serialise XML data was vulnerable to Denial of Service attacks");
            assertThat(vuln.getDescription()).isEqualTo("""
                    Those using Woodstox to parse XML data may be vulnerable to Denial of Service attacks (DOS) if DTD support is enabled. \
                    If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow. \
                    This effect may support a denial of service attack.""");
            assertThat(vuln.getCreated()).isNotNull();
            assertThat(vuln.getPublished()).isInSameDayAs("2022-09-16");
            assertThat(vuln.getUpdated()).isInSameDayAs("2023-02-09");
            assertThat(vuln.getCvssV2BaseScore()).isNull();
            assertThat(vuln.getCvssV2Vector()).isNull();
            assertThat(vuln.getCvssV3BaseScore()).isEqualByComparingTo("6.5");
            assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
            assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);
            assertThat(vuln.getCwes()).containsOnly(121, 787);
            assertThat(vuln.getPatchedVersions()).isEqualTo("6.4.0, 5.4.0");
            assertThat(vuln.getReferences()).isEqualTo("""
                    * [https://access.redhat.com/security/cve/CVE-2022-40152](https://access.redhat.com/security/cve/CVE-2022-40152)
                    * [https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47434](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47434)
                    * [https://github.com/FasterXML/woodstox](https://github.com/FasterXML/woodstox)
                    * [https://github.com/FasterXML/woodstox/issues/157](https://github.com/FasterXML/woodstox/issues/157)
                    * [https://github.com/FasterXML/woodstox/issues/160](https://github.com/FasterXML/woodstox/issues/160)
                    * [https://github.com/FasterXML/woodstox/pull/159](https://github.com/FasterXML/woodstox/pull/159)
                    * [https://github.com/advisories/GHSA-3f7h-mf4q-vrm4](https://github.com/advisories/GHSA-3f7h-mf4q-vrm4)
                    * [https://github.com/x-stream/xstream/issues/304](https://github.com/x-stream/xstream/issues/304)
                    * [https://nvd.nist.gov/vuln/detail/CVE-2022-40152](https://nvd.nist.gov/vuln/detail/CVE-2022-40152)
                    * [https://www.cve.org/CVERecord?id=CVE-2022-40152](https://www.cve.org/CVERecord?id=CVE-2022-40152)
                    """);
            assertThat(vuln.getVulnerableSoftware()).isEmpty();
        });

        assertThat(qm.getCount(ComponentAnalysisCache.class)).isZero();

        assertThat(NOTIFICATIONS).satisfiesExactly(
                notification ->
                        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name()),
                notification ->
                        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name())
        );

        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Accept", equalTo("application/protobuf"))
                .withHeader("Content-Type", equalTo("application/protobuf"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent())));

        wireMock.verify(exactly(3), postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Accept", equalTo("application/protobuf"))
                .withHeader("Content-Type", equalTo("application/protobuf"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent())));

        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Accept", equalTo("application/protobuf"))
                .withHeader("Content-Type", equalTo("application/protobuf"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent())));
    }

    @Test
    public void testAnalyzeWithNoVulnerabilities() {
        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/protobuf")
                        .withBody(ScanResponse.newBuilder()
                                .addResults(Result.newBuilder()
                                        .setClass_("lang-pkgs")
                                        .setTarget("java")
                                        .setType("jar")
                                        .build())
                                .build()
                                .toByteArray())));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).isEmpty();

        assertThat(qm.getCount(ComponentAnalysisCache.class)).isZero();

        assertThat(NOTIFICATIONS).satisfiesExactly(
                notification ->
                        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name())
                );

        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob")));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs")));
    }

    @Test
    public void testAnalyzeWithConnectionError() {
        wireMock.stubFor(any(anyUrl())
                .willReturn(aResponse()
                        .withFault(Fault.CONNECTION_RESET_BY_PEER)));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        assertThat(qm.getCount(ComponentAnalysisCache.class)).isZero();

        assertThat(NOTIFICATIONS).satisfiesExactly(
                notification -> {
                    assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
                    assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name());
                },
                notification -> {
                    assertThat(notification.getGroup()).isEqualTo(NotificationGroup.ANALYZER.name());
                    assertThat(notification.getLevel()).isEqualTo(NotificationLevel.ERROR);
                    assertThat(notification.getContent()).isEqualTo("""
                            An error occurred while communicating with a vulnerability intelligence source. \
                            Check log for details. Connection reset""");
                }
        );

        wireMock.verify(exactly(1), postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob")));
        wireMock.verify(exactly(0), postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan")));
        wireMock.verify(exactly(0), postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs")));
    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

}