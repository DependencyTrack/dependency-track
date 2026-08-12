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
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import alpine.security.crypto.DataEncryption;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.matching.RequestPatternBuilder;
import jakarta.json.Json;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.VulnDbAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.jdo.Query;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET;

class VulnDBAnalysisTaskTest extends PersistenceCapableTest {

    @RegisterExtension
    static final WireMockExtension wm = WireMockExtension.newInstance()
            .configureStaticDsl(true)
            .build();

    private static final Subscription SUBSCRIPTION = new Subscription(NotificationSubscriber.class);

    @BeforeAll
    public static void beforeClass() {
        NotificationService.getInstance().subscribe(SUBSCRIPTION);
    }

    @BeforeEach
    public void setUp() throws Exception {
        qm.createConfigProperty(
                SCANNER_VULNDB_ENABLED.getGroupName(),
                SCANNER_VULNDB_ENABLED.getPropertyName(),
                "true",
                SCANNER_VULNDB_ENABLED.getPropertyType(),
                SCANNER_VULNDB_ENABLED.getDescription());
        qm.createConfigProperty(
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                "86400",
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyType(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getDescription());
        qm.createConfigProperty(
                SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getGroupName(),
                SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getPropertyName(),
                "secret",
                SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getPropertyType(),
                SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getDescription());
        qm.createConfigProperty(
                SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getGroupName(),
                SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getPropertyName(),
                DataEncryption.encryptAsString("secret"),
                SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getPropertyType(),
                SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getDescription());
    }

    @AfterEach
    public void tearDown() {
        NOTIFICATIONS.clear();
    }

    @AfterAll
    public static void afterClass() {
        NotificationService.getInstance().unsubscribe(SUBSCRIPTION);
    }

    @Test
    void testIsCapable() {
        final var asserts = new SoftAssertions();

        for (final Map.Entry<String, Boolean> test : Map.of(
                "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*", true,
                "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*", true
        ).entrySet()) {
            final var component = new Component();
            component.setCpe(test.getKey());
            asserts.assertThat(new VulnDbAnalysisTask(wm.baseUrl()).isCapable(component)).isEqualTo(test.getValue());
        }

        asserts.assertAll();
    }

    @Test
    void testAnalyzeWithOneIssue() {
        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .withHeader("X-User-Agent", equalTo("Dependency Track (https://github.com/DependencyTrack/dependency-track)"))
                .withQueryParam("cpe", equalTo("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""                                
                                {
                                  "current_page": 1,
                                  "total_entries": 1,
                                  "results": [
                                    {
                                      "vulndb_id": 1,
                                      "title": "test title",
                                      "classifications": [
                                        {
                                          "id": 1,
                                          "name": "test vulnerability",
                                          "longname": "test vulnerability 1 1",
                                          "description": "test test",
                                          "mediumtext": "some text"
                                        }
                                      ],
                                      "authors": [
                                        {
                                          "id": 23,
                                          "name": "test author",
                                          "company": "test company"
                                        }
                                      ],
                                      "ext_references": [
                                        {
                                          "type": "external test reference",
                                          "value": "external test reference value"
                                        }
                                      ],
                                      "ext_texts": [
                                        {
                                          "type": "external test texts",
                                          "value": "external test texts value"
                                        }
                                      ],
                                      "cvss_metrics": [
                                                                
                                      ],
                                      "cvss_version_three_metrics": [
                                                                
                                      ],
                                      "nvd_additional_information": [
                                        {
                                          "summary": "test summary",
                                          "cwe_id": "test1",
                                          "cve_id": "test4"
                                        }
                                      ],
                                      "vendors": [
                                        {
                                          "vendor": {
                                            "id": 1,
                                            "name": "vendor one test",
                                            "short_name": "test",
                                            "vendor_url": "http://test.com",
                                            "products": [
                                              {
                                                "id": 45,
                                                "name": "test product name",
                                                "versions": [
                                                  {
                                                    "id": 2,
                                                    "name": "version 2",
                                                    "affected": false,
                                                    "cpe": [
                                                      {
                                                        "cpe": "test cpe",
                                                        "type": "test type"
                                                      }
                                                    ]
                                                  }
                                                ]
                                              }
                                            ]
                                          }
                                        }
                                      ]
                                    }
                                  ]
                                }
                                """)));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("6.4.0");
        component.setCpe("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        new VulnDbAnalysisTask(wm.baseUrl()).inform(new VulnDbAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);

        assertThat(vulnerabilities).hasSize(1);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        assertThat(cacheEntries).hasSize(1);

        final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        assertThat(cacheEntry.getTarget()).isEqualTo("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        final var result = new ArrayList<>();
        result.add(1);
        assertThat(cacheEntry.getResult())
                .containsEntry("vulnIds", Json.createArrayBuilder(result).build());
    }

    @Test
    void testAnalyzeWithNoIssue() {
        stubFor(get(urlPathEqualTo("/api/v1/vulnerabilities/find_by_cpe"))
                .withHeader("X-User-Agent", equalTo("Dependency Track (https://github.com/DependencyTrack/dependency-track)"))
                .withQueryParam("cpe", equalTo("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*"))
                .willReturn(aResponse()
                        .withStatus(404)));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("6.4.0");
        component.setCpe("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        new VulnDbAnalysisTask(wm.baseUrl()).inform(new VulnDbAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);

        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        assertThat(cacheEntries).hasSize(1);

        final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        assertThat(cacheEntry.getTarget()).isEqualTo("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        assertThat(cacheEntry.getResult())
                .isNull();
    }

    @Test
    void testAnalyzeWithCurrentCache() {
        var vuln = new Vulnerability();
        vuln.setVulnId("VULNDB-001");
        vuln.setSource(Vulnerability.Source.VULNDB);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, wm.baseUrl(),
                Vulnerability.Source.VULNDB.name(), "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*", new Date(),
                Json.createObjectBuilder()
                        .add("vulnIds", Json.createArrayBuilder().add(vuln.getId()))
                        .build());

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("5.0.0");
        component.setCpe("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        new VulnDbAnalysisTask(wm.baseUrl()).inform(new VulnDbAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(1);

        verify(0, RequestPatternBuilder.allRequests());
    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

}