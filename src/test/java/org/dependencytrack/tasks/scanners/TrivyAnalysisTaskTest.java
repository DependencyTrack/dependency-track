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
import com.github.packageurl.PackageURL;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.TrivyAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import jakarta.json.Json;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
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
    public void testShouldAnalyzeWhenCacheIsCurrent() throws Exception {
        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, wireMock.baseUrl(),
                Vulnerability.Source.TRIVY.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", new Date(),
                Json.createObjectBuilder()
                        .add("vulnIds", Json.createArrayBuilder().add(123))
                        .build());

        assertThat(new TrivyAnalysisTask().shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isFalse();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsNotCurrent() throws Exception {
        assertThat(new TrivyAnalysisTask().shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isTrue();
    }

    @Test
    public void testAnalyzeWithRetry() {
        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {}
                                """)));

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
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "os": {
                                    "family": "",
                                    "name": "",
                                    "eosl": false,
                                    "extended": false
                                  },
                                  "results": [
                                    {
                                      "target": "Java",
                                      "vulnerabilities": [
                                        {
                                          "vulnerability_id": "CVE-2022-40152",
                                          "pkg_name": "com.fasterxml.woodstox:woodstox-core",
                                          "installed_version": "5.0.0",
                                          "fixed_version": "6.4.0, 5.4.0",
                                          "title": "woodstox-core: woodstox to serialise XML data was vulnerable to Denial of Service attacks",
                                          "description": "Those using Woodstox to parse XML data may be vulnerable to Denial of Service attacks (DOS) if DTD support is enabled. If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow. This effect may support a denial of service attack.",
                                          "severity": "MEDIUM",
                                          "references": [
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
                                          ],
                                          "pkg_identifier": {
                                            "purl": "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0",
                                            "bom_ref": ""
                                          },
                                          "layer": {
                                            "digest": "",
                                            "diff_id": "",
                                            "created_by": ""
                                          },
                                          "severity_source": "ghsa",
                                          "cvss": {
                                            "ghsa": {
                                              "v2_vector": "",
                                              "v3_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                                              "v2_score": 0,
                                              "v3_score": 6.5
                                            },
                                            "nvd": {
                                              "v2_vector": "",
                                              "v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                              "v2_score": 0,
                                              "v3_score": 7.5
                                            },
                                            "redhat": {
                                              "v2_vector": "",
                                              "v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                              "v2_score": 0,
                                              "v3_score": 7.5
                                            }
                                          },
                                          "cwe_ids": [
                                            "CWE-787",
                                            "CWE-121"
                                          ],
                                          "primary_url": "https://avd.aquasec.com/nvd/cve-2022-40152",
                                          "published_date": "2022-09-16T10:15:09.877Z",
                                          "last_modified_date": "2023-02-09T01:36:03.637Z",
                                          "custom_advisory_data": null,
                                          "custom_vuln_data": null,
                                          "vendor_ids": [],
                                          "data_source": {
                                            "id": "ghsa",
                                            "name": "GitHub Security Advisory Maven",
                                            "url": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven"
                                          },
                                          "vendor_severity": {
                                            "amazon": "MEDIUM",
                                            "ghsa": "MEDIUM",
                                            "nvd": "HIGH",
                                            "redhat": "MEDIUM"
                                          },
                                          "pkg_path": "",
                                          "pkg_id": "",
                                          "status": 3
                                        }
                                      ],
                                      "misconfigurations": [],
                                      "class": "lang-pkgs",
                                      "type": "jar",
                                      "packages": [],
                                      "custom_resources": [],
                                      "secrets": [],
                                      "licenses": []
                                    }
                                  ]
                                }
                                """)));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {}
                                """)));

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

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(component));

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

        assertThat(qm.getCount(ComponentAnalysisCache.class)).isOne();

        assertThat(NOTIFICATIONS).satisfiesExactly(notification ->
                assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name()));

        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent()))
                .withRequestBody(equalToJson("""
                        {
                          "diff_id": "${json-unit.regex}(^sha256:[a-f0-9]{64}$)",
                          "blob_info": {
                            "schema_version": 2,
                            "os": {
                              "eosl": false,
                              "extended": false
                            },
                            "applications": [
                              {
                                "type": "jar",
                                "packages": [
                                  {
                                    "name": "com.fasterxml.woodstox:woodstox-core",
                                    "version": "5.0.0",
                                    "src_name": "com.fasterxml.woodstox:woodstox-core",
                                    "src_version": "5.0.0",
                                    "licenses": [],
                                    "layer": {
                                      "eosl": false,
                                      "extended": false
                                    }
                                  }
                                ],
                                "libraries": [
                                  {
                                    "name": "com.fasterxml.woodstox:woodstox-core",
                                    "version": "5.0.0",
                                    "src_name": "com.fasterxml.woodstox:woodstox-core",
                                    "src_version": "5.0.0",
                                    "licenses": [],
                                    "layer": {
                                      "eosl": false,
                                      "extended": false
                                    }
                                  }
                                ]
                              }
                            ]
                          }
                        }
                        """)));

        wireMock.verify(exactly(3), postRequestedFor(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent()))
                .withRequestBody(equalToJson("""
                        {
                           "target": "${json-unit.regex}(^sha256:[a-f0-9]{64}$)",
                           "artifact_id": "${json-unit.regex}(^sha256:[a-f0-9]{64}$)",
                           "blob_ids": [
                             "${json-unit.regex}(^sha256:[a-f0-9]{64}$)"
                           ],
                           "options": {
                             "vuln_type": [
                               "os",
                               "library"
                             ],
                             "scanners": [
                               "vuln"
                             ]
                           }
                         }
                        """)));

        wireMock.verify(postRequestedFor(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .withHeader("Trivy-Token", equalTo("token"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent()))
                .withRequestBody(equalToJson("""
                        {
                          "blob_ids": [
                            "${json-unit.regex}(^sha256:[a-f0-9]{64}$)"
                          ]
                        }
                        """)));
    }

    @Test
    public void testAnalyzeWithNoVulnerabilities() {
        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/PutBlob"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {}
                                """)));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "os": {
                                    "family": "",
                                    "name": "",
                                    "eosl": false,
                                    "extended": false
                                  },
                                  "results": [
                                    {
                                      "target": "Java",
                                      "vulnerabilities": [],
                                      "misconfigurations": [],
                                      "class": "lang-pkgs",
                                      "type": "jar",
                                      "packages": [],
                                      "custom_resources": [],
                                      "secrets": [],
                                      "licenses": []
                                    }
                                  ]
                                }
                                """)));

        wireMock.stubFor(post(urlPathEqualTo("/twirp/trivy.cache.v1.Cache/DeleteBlobs"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {}
                                """)));

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

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).isEmpty();

        assertThat(qm.getCount(ComponentAnalysisCache.class)).isZero();

        assertThat(NOTIFICATIONS).isEmpty();

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

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(List.of(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        assertThat(qm.getCount(ComponentAnalysisCache.class)).isZero();

        assertThat(NOTIFICATIONS).satisfiesExactly(notification -> {
            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.ANALYZER.name());
            assertThat(notification.getLevel()).isEqualTo(NotificationLevel.ERROR);
            assertThat(notification.getContent()).isEqualTo("""
                    An error occurred while communicating with a vulnerability intelligence source. \
                    Check log for details. Connection reset""");
        });

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