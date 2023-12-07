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
import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.TrivyAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;

import javax.jdo.Query;
import javax.json.Json;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_ENABLED;
import static org.mockserver.model.HttpError.error;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class TrivyAnalysisTaskTest extends PersistenceCapableTest {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(SCANNER_TRIVY_ENABLED.getGroupName(),
                SCANNER_TRIVY_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "trivy");
        qm.createConfigProperty(SCANNER_TRIVY_API_TOKEN.getGroupName(),
                SCANNER_TRIVY_API_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("token"),
                IConfigProperty.PropertyType.STRING,
                "token");
        qm.createConfigProperty(SCANNER_TRIVY_BASE_URL.getGroupName(),
                SCANNER_TRIVY_BASE_URL.getPropertyName(),
                "http://localhost:8081",
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
        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, "http://localhost:8081",
                Vulnerability.Source.NVD.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", new Date(),
                Json.createObjectBuilder()
                        .add("vulnIds", Json.createArrayBuilder().add(123))
                        .build());

        assertThat(new TrivyAnalysisTask().shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isTrue();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsNotCurrent() throws Exception {
        assertThat(new TrivyAnalysisTask().shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isTrue();
    }

    @Test
    public void testAnalyzeWithNoIssues() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/twirp/trivy.scanner.v1.Scanner/Scan"))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""
                                {
                                        "os":{}
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

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        // final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        // final List<ComponentAnalysisCache> cacheEntries = cacheQuery.executeList();
        // assertThat(cacheEntries).hasSize(1);

        // final ComponentAnalysisCache cacheEntry = cacheEntries.get(0);
        // assertThat(cacheEntry.getTarget()).isEqualTo("pkg:maven/com.fasterxml.woodstox/woodstox-core@6.4.0");
        // assertThat(cacheEntry.getResult())
        //         .containsEntry("vulnIds", Json.createArrayBuilder().build());
    }

    @Test
    //TODO: THIS
    public void testAnalyzeWithConnectionError() {
        mockServer
                .when(request().withPath("/twirp/trivy.scanner.v1.Scanner/Scan"))
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

        new TrivyAnalysisTask().inform(new TrivyAnalysisEvent(List.of(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).isEmpty();
    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }
}