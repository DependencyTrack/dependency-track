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
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import alpine.security.crypto.DataEncryption;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.VulnDbAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.verify.VerificationTimes;

import javax.jdo.Query;
import javax.json.Json;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.model.ConfigPropertyConstants.*;
import static org.mockserver.model.HttpError.error;
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
    public void testAnalyzeWithNoIssues() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/api/v1/vulnerabilities/find_by_cpe")
                        .withHeader(new Header("X-User-Agent", "VulnDB Data Mirror (https://github.com/stevespringett/vulndb-data-mirror)"))
                        .withQueryStringParameter("cpe", "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*" ))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""
                                {
                                   "jsonapi": {
                                     "version": "1.0"
                                   },
                                   "data": [],
                                   "links": {
                                     "self": "/orgs/da563045-a462-421a-ae47-53239fe46612/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%406.4.0/issues?version=2023-01-04&limit=1000&offset=0"
                                   },
                                   "meta": {
                                     "package": {
                                       "name": "woodstox-core",
                                       "type": "maven",
                                       "url": "pkg:maven/com.fasterxml.woodstox/woodstox-core@6.4.0",
                                       "version": "6.4.0"
                                     }
                                   }
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
        String logMessages = mockServer
                .retrieveLogMessages(
                        request()
                );

        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        assertThat(cacheEntries).hasSize(1);

        final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        assertThat(cacheEntry.getTarget()).isEqualTo("cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*");
        assertThat(cacheEntry.getResult())
                .containsEntry("vulnIds", Json.createArrayBuilder().build());
    }

//    @Test
//    public void testAnalyzeWithError() {
//        mockServer
//                .when(request()
//                        .withMethod("GET")
//                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
//                        .withQueryStringParameter("version", "version"))
//                .respond(response()
//                        .withStatusCode(400)
//                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
//                        .withBody("""
//                                {
//                                  "jsonapi": {
//                                    "version": "1.0"
//                                  },
//                                  "errors": [
//                                    {
//                                      "id": "0f12fd75-c80a-4c15-929b-f7794eb3dd4f",
//                                      "links": {
//                                        "about": "https://docs.snyk.io/more-info/error-catalog#snyk-ossi-2010-invalid-purl-has-been-provided"
//                                      },
//                                      "status": "400",
//                                      "code": "SNYK-OSSI-2010",
//                                      "title": "Invalid PURL has been provided",
//                                      "detail": "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0%",
//                                      "source": {
//                                        "pointer": "/orgs/0d581750-c5d7-4acf-9ff9-4a5bae31cbf1/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0%25/issues"
//                                      },
//                                      "meta": {
//                                        "links": [
//                                          "https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst"
//                                        ]
//                                      }
//                                    }
//                                  ]
//                                }
//                                """));
//
//        var project = new Project();
//        project.setName("acme-app");
//        project = qm.createProject(project, null, false);
//
//        var component = new Component();
//        component.setProject(project);
//        component.setGroup("com.fasterxml.woodstox");
//        component.setName("woodstox-core");
//        component.setVersion("5.0.0");
//        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
//        component = qm.createComponent(component, false);
//
//        new VulnDbAnalysisTask().inform(new VulnDbAnalysisEvent(List.of(component)));
//
//        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
//        assertThat(vulnerabilities).hasSize(0);
//
//        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
//        assertThat(cacheQuery.executeList()).isEmpty();
//    }
//
//    @Test
//    public void testAnalyzeWithUnspecifiedError() {
//        mockServer
//                .when(request()
//                        .withMethod("GET")
//                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
//                        .withQueryStringParameter("version", "version"))
//                .respond(response()
//                        .withStatusCode(403)
//                );
//
//        var project = new Project();
//        project.setName("acme-app");
//        project = qm.createProject(project, null, false);
//
//        var component = new Component();
//        component.setProject(project);
//        component.setGroup("com.fasterxml.woodstox");
//        component.setName("woodstox-core");
//        component.setVersion("5.0.0");
//        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
//        component = qm.createComponent(component, false);
//
//        new VulnDbAnalysisTask().inform(new VulnDbAnalysisEvent(List.of(component)));
//
//        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
//        assertThat(vulnerabilities).hasSize(0);
//
//        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
//        assertThat(cacheQuery.executeList()).isEmpty();
//    }
//
//    @Test
//    public void testAnalyzeWithConnectionError() {
//        mockServer
//                .when(request().withPath("/rest/.+"))
//                .error(error().withDropConnection(true));
//
//        var project = new Project();
//        project.setName("acme-app");
//        project = qm.createProject(project, null, false);
//
//        var component = new Component();
//        component.setProject(project);
//        component.setGroup("com.fasterxml.woodstox");
//        component.setName("woodstox-core");
//        component.setVersion("5.0.0");
//        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
//        component = qm.createComponent(component, false);
//
//        new VulnDbAnalysisTask().inform(new VulnDbAnalysisEvent(List.of(component)));
//
//        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
//        assertThat(vulnerabilities).hasSize(0);
//
//        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
//        assertThat(cacheQuery.executeList()).isEmpty();
//    }
//
//    @Test
//    public void testAnalyzeWithCurrentCache() {
//        var vuln = new Vulnerability();
//        vuln.setVulnId("VULNDB-001");
//        vuln.setSource(Vulnerability.Source.VULNDB);
//        vuln.setSeverity(Severity.HIGH);
//        vuln = qm.createVulnerability(vuln, false);
//
//        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, "http://localhost:1080",
//                Vulnerability.Source.VULNDB.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", new Date(),
//                Json.createObjectBuilder()
//                        .add("vulnIds", Json.createArrayBuilder().add(vuln.getId()))
//                        .build());
//
//        var project = new Project();
//        project.setName("acme-app");
//        project = qm.createProject(project, null, false);
//
//        var component = new Component();
//        component.setProject(project);
//        component.setGroup("com.fasterxml.woodstox");
//        component.setName("woodstox-core");
//        component.setVersion("5.0.0");
//        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
//        component = qm.createComponent(component, false);
//
//        new VulnDbAnalysisTask().inform(new VulnDbAnalysisEvent(component));
//
//        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
//        assertThat(vulnerabilities).hasSize(1);
//
//        mockServer.verifyZeroInteractions();
//    }
//
//    @Test
//    public void testAnalyzeWithDeprecatedApiVersion() throws Exception {
//        mockServer
//                .when(request()
//                        .withMethod("GET")
//                        .withPath("/rest/.+"))
//                .respond(response()
//                        .withStatusCode(200)
//                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
//                        .withHeader("Sunset", "Wed, 11 Nov 2021 11:11:11 GMT")
//                        .withBody("""
//                                {
//                                   "jsonapi": {
//                                     "version": "1.0"
//                                   },
//                                   "data": [],
//                                   "links": {
//                                     "self": "/orgs/da563045-a462-421a-ae47-53239fe46612/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%406.4.0/issues?version=2023-01-04&limit=1000&offset=0"
//                                   },
//                                   "meta": {
//                                     "package": {
//                                       "name": "woodstox-core",
//                                       "type": "maven",
//                                       "url": "pkg:maven/com.fasterxml.woodstox/woodstox-core@6.4.0",
//                                       "version": "6.4.0"
//                                     }
//                                   }
//                                 }
//                                """));
//
//        var project = new Project();
//        project.setName("acme-app");
//        project = qm.createProject(project, null, false);
//
//        var component = new Component();
//        component.setProject(project);
//        component.setGroup("com.fasterxml.woodstox");
//        component.setName("woodstox-core");
//        component.setVersion("5.0.0");
//        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
//        component = qm.createComponent(component, false);
//
//        new VulnDbAnalysisTask().inform(new VulnDbAnalysisEvent(component));
//
//        assertConditionWithTimeout(() -> NOTIFICATIONS.size() > 0, Duration.ofSeconds(5));
//        assertThat(NOTIFICATIONS).anySatisfy(notification -> {
//            assertThat(notification.getScope()).isEqualTo(NotificationScope.SYSTEM.name());
//            assertThat(notification.getLevel()).isEqualTo(NotificationLevel.WARNING);
//            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.ANALYZER.name());
//            assertThat(notification.getTitle()).isNotEmpty();
//            assertThat(notification.getContent()).contains("Wed, 11 Nov 2021 11:11:11 GMT");
//            assertThat(notification.getSubject()).isNull();
//        });
//    }
//
//    @Test
//    public void testSendsUserAgent() {
//        mockServer
//                .when(request()
//                        .withMethod("GET")
//                        .withPath("/rest/.+"))
//                .respond(response()
//                        .withStatusCode(404));
//
//        var project = new Project();
//        project.setName("acme-app");
//        project = qm.createProject(project, null, false);
//
//        var component = new Component();
//        component.setProject(project);
//        component.setGroup("com.fasterxml.woodstox");
//        component.setName("woodstox-core");
//        component.setVersion("5.0.0");
//        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
//        component = qm.createComponent(component, false);
//
//        new VulnDbAnalysisTask().inform(new VulnDbAnalysisEvent(component));
//
//        mockServer.verify(
//                request().withHeader("User-Agent", ManagedHttpClientFactory.getUserAgent()),
//                VerificationTimes.once()
//        );
//    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

}