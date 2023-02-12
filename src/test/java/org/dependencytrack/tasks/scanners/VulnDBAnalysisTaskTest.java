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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import alpine.model.IConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import alpine.security.crypto.DataEncryption;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.VulnDbAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;

import javax.jdo.Query;
import javax.json.Json;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class VulnDBAnalysisTaskTest extends PersistenceCapableTest {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(SCANNER_VULNDB_ENABLED.getGroupName(),
                SCANNER_VULNDB_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "vulndb");
        qm.createConfigProperty(SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                "86400",
                IConfigProperty.PropertyType.STRING,
                "cache");
        qm.createConfigProperty(SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getGroupName(),
                SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getPropertyName(),
                DataEncryption.encryptAsString("secret"),
                IConfigProperty.PropertyType.STRING,
                "secret");
        qm.createConfigProperty(SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getGroupName(),
                SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getPropertyName(),
                DataEncryption.encryptAsString("secret"),
                IConfigProperty.PropertyType.STRING,
                "secret");
    }

    @After
    public void tearDown() {
        mockServer.reset();
        NOTIFICATIONS.clear();
    }

    @AfterClass
    public static void afterClass() {
        mockServer.stop();
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
    }

    @Test
    public void testIsCapable() {
        final var asserts = new SoftAssertions();

        for (final Map.Entry<String, Boolean> test : Map.of(
                "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*", true,
                "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*", true
        ).entrySet()) {
            final var component = new Component();
            component.setCpe(test.getKey());
            asserts.assertThat(new VulnDbAnalysisTask("http://localhost:1080").isCapable(component)).isEqualTo(test.getValue());
        }

        asserts.assertAll();
    }

    @Test
    public void testAnalyzeWithOneIssue() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/api/v1/vulnerabilities/find_by_cpe")
                        .withHeader(new Header("X-User-Agent", "Dependency Track (https://github.com/DependencyTrack/dependency-track)"))
                        .withQueryStringParameter("cpe", "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*"))
                .respond(response()
                        .withStatusCode(200)
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
                                """));

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

        new VulnDbAnalysisTask("http://localhost:1080").inform(new VulnDbAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);

        assertThat(vulnerabilities).hasSize(1);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        assertThat(cacheEntries).hasSize(1);

        final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        assertThat(cacheEntry.getTarget()).isEqualTo("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        List result = new ArrayList<Integer>();
        result.add(1);
        assertThat(cacheEntry.getResult())
                .containsEntry("vulnIds", Json.createArrayBuilder(result).build());
    }

    @Test
    public void testAnalyzeWithNoIssue() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/api/v1/vulnerabilities/find_by_cpe")
                        .withHeader(new Header("X-User-Agent", "Dependency Track (https://github.com/DependencyTrack/dependency-track)"))
                        .withQueryStringParameter("cpe", "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*"))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""                                
                                {
                                  "current_page": 1,
                                  "total_entries": 1,
                                  "results": []
                                }
                                """));

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

        new VulnDbAnalysisTask("http://localhost:1080").inform(new VulnDbAnalysisEvent(component));

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
    public void testAnalyzeWithCurrentCache() {
        var vuln = new Vulnerability();
        vuln.setVulnId("VULNDB-001");
        vuln.setSource(Vulnerability.Source.VULNDB);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, "http://localhost:1080",
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

        new VulnDbAnalysisTask("http://localhost:1080").inform(new VulnDbAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(1);

        mockServer.verifyZeroInteractions();
    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

}