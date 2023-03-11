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

import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.SnykAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.verify.VerificationTimes;

import javax.jdo.Query;
import javax.json.Json;
import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_VERSION;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ORG_ID;
import static org.mockserver.model.HttpError.error;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class SnykAnalysisTaskTest extends PersistenceCapableTest {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(SCANNER_SNYK_ENABLED.getGroupName(),
                SCANNER_SNYK_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "snyk");
        qm.createConfigProperty(SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                "86400",
                IConfigProperty.PropertyType.STRING,
                "cache");
        qm.createConfigProperty(SCANNER_SNYK_API_TOKEN.getGroupName(),
                SCANNER_SNYK_API_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("token"),
                IConfigProperty.PropertyType.STRING,
                "token");
        qm.createConfigProperty(SCANNER_SNYK_ORG_ID.getGroupName(),
                SCANNER_SNYK_ORG_ID.getPropertyName(),
                "orgid",
                IConfigProperty.PropertyType.STRING,
                "orgid");
        qm.createConfigProperty(SCANNER_SNYK_API_VERSION.getGroupName(),
                SCANNER_SNYK_API_VERSION.getPropertyName(),
                "version",
                IConfigProperty.PropertyType.STRING,
                "version");
        qm.createConfigProperty(SCANNER_SNYK_BASE_URL.getGroupName(),
                SCANNER_SNYK_BASE_URL.getPropertyName(),
                "http://localhost:1080",
                IConfigProperty.PropertyType.STRING,
                "url");
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
                "pkg:maven/com.fasterxml.woodstox/woodstox-core", false, // Missing version
                "pkg:golang/github.com/CycloneDX/cyclonedx-go@0.7.0", false, // Unsupported type
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", true,
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz", true
        ).entrySet()) {
            final var component = new Component();
            component.setPurl(test.getKey());
            asserts.assertThat(new SnykAnalysisTask().isCapable(component)).isEqualTo(test.getValue());
        }

        asserts.assertAll();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsCurrent() throws Exception {
        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, "http://localhost:1080",
                Vulnerability.Source.SNYK.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", new Date(),
                Json.createObjectBuilder()
                        .add("vulnIds", Json.createArrayBuilder().add(123))
                        .build());

        assertThat(new SnykAnalysisTask().shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isFalse();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsNotCurrent() throws Exception {
        assertThat(new SnykAnalysisTask().shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isTrue();
    }

    @Test
    public void testAnalyzeWithRateLimiting() {
        mockServer
                .when(request(), Times.exactly(2))
                .respond(response().withStatusCode(429));

        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
                        .withQueryStringParameter("version", "version"))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""
                                {
                                   "jsonapi": {
                                     "version": "1.0"
                                   },
                                   "data": [
                                     {
                                       "id": "SNYK-JAVA-COMFASTERXMLWOODSTOX-3091135",
                                       "type": "issue",
                                       "attributes": {
                                         "key": "SNYK-JAVA-COMFASTERXMLWOODSTOX-3091135",
                                         "title": "Denial of Service (DoS)",
                                         "type": "package_vulnerability",
                                         "created_at": "2022-10-31T11:25:51.137662Z",
                                         "updated_at": "2022-11-26T01:10:27.643959Z",
                                         "description": "## Overview\\n\\nAffected versions of this package are vulnerable to Denial of Service (DoS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stack overflow.\\n\\n## Details\\n\\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\\n\\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\\n\\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\\n\\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\\n\\nTwo common types of DoS vulnerabilities:\\n\\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\\n\\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\\n\\n## Remediation\\nUpgrade `com.fasterxml.woodstox:woodstox-core` to version 5.0.4, 6.0.4 or higher.\\n## References\\n- [GitHub Issue](https://github.com/FasterXML/woodstox/issues/157)\\n- [GitHub Issue](https://github.com/x-stream/xstream/issues/304#issuecomment-1254647926)\\n- [GitHub PR](https://github.com/FasterXML/woodstox/pull/159)\\n",
                                         "problems": [
                                           {
                                             "id": "CVE-2022-40152",
                                             "source": "CVE"
                                           },
                                           {
                                             "id": "GHSA-3f7h-mf4q-vrm4",
                                             "source": "GHSA"
                                           }
                                         ],
                                         "coordinates": [
                                           {
                                             "remedies": [
                                               {
                                                 "type": "indeterminate",
                                                 "description": "Upgrade the package version to 5.0.4,6.0.4 to fix this vulnerability",
                                                 "details": {
                                                   "upgrade_package": "5.0.4,6.0.4"
                                                 }
                                               }
                                             ],
                                             "representation": [
                                               "[,5.0.4)",
                                               "[6.0.0.pr1,6.0.4)"
                                             ]
                                           }
                                         ],
                                         "severities": [
                                           {
                                             "source": "Snyk",
                                             "level": "medium",
                                             "score": 5.3,
                                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
                                           },
                                           {
                                             "source": "NVD",
                                             "level": "high",
                                             "score": 7.5,
                                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                           },
                                           {
                                             "source": "Red Hat",
                                             "level": "high",
                                             "score": 7.5,
                                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                                           }
                                         ],
                                         "effective_severity_level": "medium",
                                         "slots": {
                                           "disclosure_time": "2022-10-31T11:15:12Z",
                                           "exploit": "Not Defined",
                                           "publication_time": "2022-10-31T16:11:28.305760Z",
                                           "references": [
                                             {
                                               "url": "https://github.com/FasterXML/woodstox/issues/157",
                                               "title": "GitHub Issue"
                                             },
                                             {
                                               "url": "https://github.com/x-stream/xstream/issues/304%23issuecomment-1254647926",
                                               "title": "GitHub Issue"
                                             },
                                             {
                                               "url": "https://github.com/FasterXML/woodstox/pull/159",
                                               "title": "GitHub PR"
                                             }
                                           ]
                                         }
                                       }
                                     }
                                   ],
                                   "links": {
                                     "self": "/orgs/fd53e445-dc38-4b25-9c8a-5f68ed79f537/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues?version=2023-01-04&limit=1000&offset=0"
                                   },
                                   "meta": {
                                     "package": {
                                       "name": "woodstox-core",
                                       "type": "maven",
                                       "url": "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0",
                                       "version": "5.0.0"
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
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(1);

        final Vulnerability vulnerability = vulnerabilities.get(0);
        assertThat(vulnerability.getVulnId()).isEqualTo("SNYK-JAVA-COMFASTERXMLWOODSTOX-3091135");
        assertThat(vulnerability.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vulnerability.getTitle()).isEqualTo("Denial of Service (DoS)");
        assertThat(vulnerability.getDescription()).startsWith("## Overview");
        assertThat(vulnerability.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
        assertThat(vulnerability.getCvssV3BaseScore()).isEqualTo(new BigDecimal("7.5"));
        assertThat(vulnerability.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(vulnerability.getCreated()).isInSameDayAs("2022-10-31");
        assertThat(vulnerability.getUpdated()).isInSameDayAs("2022-11-26");
        assertThat(vulnerability.getRecommendation()).contains("Upgrade the package version to 5.0.4,6.0.4 to fix this vulnerability");
        assertThat(vulnerability.getAliases()).satisfiesExactly(
                alias -> {
                    assertThat(alias.getSnykId()).isEqualTo("SNYK-JAVA-COMFASTERXMLWOODSTOX-3091135");
                    assertThat(alias.getCveId()).isEqualTo("CVE-2022-40152");
                    assertThat(alias.getGhsaId()).isEqualTo("GHSA-3f7h-mf4q-vrm4");
                }
        );
        assertThat(vulnerability.getReferences()).isEqualTo("""
                * [https://github.com/FasterXML/woodstox/issues/157](https://github.com/FasterXML/woodstox/issues/157)
                * [https://github.com/x-stream/xstream/issues/304%23issuecomment-1254647926](https://github.com/x-stream/xstream/issues/304%23issuecomment-1254647926)
                * [https://github.com/FasterXML/woodstox/pull/159](https://github.com/FasterXML/woodstox/pull/159)
                """);
        assertThat(vulnerability.getVulnerableSoftware()).hasSize(1);

        final VulnerableSoftware vs = vulnerability.getVulnerableSoftware().get(0);
        assertThat(vs.getPurlType()).isEqualTo("maven");
        assertThat(vs.getPurlNamespace()).isEqualTo("com.fasterxml.woodstox");
        assertThat(vs.getPurlName()).isEqualTo("woodstox-core");
        assertThat(vs.getVersionStartIncluding()).isEqualTo("6.0.0.pr1");
        assertThat(vs.getVersionEndExcluding()).isEqualTo("6.0.4");
        assertThat(qm.getAffectedVersionAttribution(vulnerability, vs, Vulnerability.Source.SNYK)).isNotNull();

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        assertThat(cacheEntries).hasSize(1);

        final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        assertThat(cacheEntry.getTargetHost()).isEqualTo("http://localhost:1080");
        assertThat(cacheEntry.getTarget()).isEqualTo("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0");
        assertThat(cacheEntry.getResult())
                .containsEntry("vulnIds", Json.createArrayBuilder().add(vulnerability.getId()).build());

        mockServer.verify(request(), VerificationTimes.exactly(3));
    }

    @Test
    public void testAnalyzeWithNoIssues() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%406.4.0/issues")
                        .withQueryStringParameter("version", "version"))
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
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@6.4.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        assertThat(cacheEntries).hasSize(1);

        final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        assertThat(cacheEntry.getTarget()).isEqualTo("pkg:maven/com.fasterxml.woodstox/woodstox-core@6.4.0");
        assertThat(cacheEntry.getResult())
                .containsEntry("vulnIds", Json.createArrayBuilder().build());
    }

    @Test
    public void testAnalyzeWithError() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
                        .withQueryStringParameter("version", "version"))
                .respond(response()
                        .withStatusCode(400)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""
                                {
                                  "jsonapi": {
                                    "version": "1.0"
                                  },
                                  "errors": [
                                    {
                                      "id": "0f12fd75-c80a-4c15-929b-f7794eb3dd4f",
                                      "links": {
                                        "about": "https://docs.snyk.io/more-info/error-catalog#snyk-ossi-2010-invalid-purl-has-been-provided"
                                      },
                                      "status": "400",
                                      "code": "SNYK-OSSI-2010",
                                      "title": "Invalid PURL has been provided",
                                      "detail": "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0%",
                                      "source": {
                                        "pointer": "/orgs/0d581750-c5d7-4acf-9ff9-4a5bae31cbf1/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0%25/issues"
                                      },
                                      "meta": {
                                        "links": [
                                          "https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst"
                                        ]
                                      }
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
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(List.of(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).isEmpty();
    }

    @Test
    public void testAnalyzeWithUnspecifiedError() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
                        .withQueryStringParameter("version", "version"))
                .respond(response()
                        .withStatusCode(403)
                );

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

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(List.of(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).isEmpty();
    }

    @Test
    public void testAnalyzeWithConnectionError() {
        mockServer
                .when(request().withPath("/rest/.+"))
                .error(error().withDropConnection(true));

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

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(List.of(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).isEmpty();
    }

    @Test
    public void testAnalyzeWithCurrentCache() {
        var vuln = new Vulnerability();
        vuln.setVulnId("SNYK-001");
        vuln.setSource(Vulnerability.Source.SNYK);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, "http://localhost:1080",
                Vulnerability.Source.SNYK.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", new Date(),
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
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(1);

        mockServer.verifyZeroInteractions();
    }

    @Test
    public void testAnalyzeWithDeprecatedApiVersion() throws Exception {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/.+"))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withHeader("Sunset", "Wed, 11 Nov 2021 11:11:11 GMT")
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
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(component));

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() > 0, Duration.ofSeconds(5));
        assertThat(NOTIFICATIONS).anySatisfy(notification -> {
            assertThat(notification.getScope()).isEqualTo(NotificationScope.SYSTEM.name());
            assertThat(notification.getLevel()).isEqualTo(NotificationLevel.WARNING);
            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.ANALYZER.name());
            assertThat(notification.getTitle()).isNotEmpty();
            assertThat(notification.getContent()).contains("Wed, 11 Nov 2021 11:11:11 GMT");
            assertThat(notification.getSubject()).isNull();
        });
    }

    @Test
    public void testAnalyzeWithMultipleTokens() throws Exception {
        final ConfigProperty configProperty =  qm.getConfigProperty(
                SCANNER_SNYK_API_TOKEN.getGroupName(),
                SCANNER_SNYK_API_TOKEN.getPropertyName());
       configProperty.setPropertyValue(DataEncryption.encryptAsString("token1;token2;token3;token4;token5"));
       qm.persist(configProperty);

        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/.+"))
                .respond(response()
                        .withStatusCode(404));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        final var components = new ArrayList<Component>();
        for (int i = 0; i < 100; i++) {
            var component = new Component();
            component.setProject(project);
            component.setGroup("com.fasterxml.woodstox");
            component.setName("component" + i);
            component.setVersion("5.0.0");
            component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
            components.add(qm.createComponent(component, false));
        }

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(components));

        mockServer.verify(request().withHeader("Authorization", "token token1"), VerificationTimes.exactly(20));
        mockServer.verify(request().withHeader("Authorization", "token token2"), VerificationTimes.exactly(20));
        mockServer.verify(request().withHeader("Authorization", "token token3"), VerificationTimes.exactly(20));
        mockServer.verify(request().withHeader("Authorization", "token token4"), VerificationTimes.exactly(20));
        mockServer.verify(request().withHeader("Authorization", "token token5"), VerificationTimes.exactly(20));
    }

    @Test
    public void testSendsUserAgent() throws Exception {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/.+"))
                .respond(response()
                        .withStatusCode(404));

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

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(component));

        mockServer.verify(
            request().withHeader("User-Agent", ManagedHttpClientFactory.getUserAgent()),
            VerificationTimes.once()
        );
    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

}