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
package org.dependencytrack.resources.v1;

import alpine.event.framework.Event;
import alpine.event.framework.SingleThreadedEventService;
import alpine.event.framework.Subscriber;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.search.IndexManager;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class SearchResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(SearchResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    private static final ConcurrentLinkedQueue<Event> EVENTS = new ConcurrentLinkedQueue<>();

    public static class EventSubscriber implements Subscriber {

        @Override
        public void inform(final Event event) {
            EVENTS.add(event);
        }

    }

    @BeforeEach
    public void before() throws Exception {
        SingleThreadedEventService.getInstance().subscribe(IndexEvent.class, EventSubscriber.class);
    }

    @AfterEach
    public void after() {
        SingleThreadedEventService.getInstance().unsubscribe(EventSubscriber.class);
        EVENTS.clear();
    }

    @Test
    void searchTest() {
        Response response = jersey.target(V1_SEARCH).queryParam("query", "tomcat").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
    }

    @Test
    void searchProjectTest() {
        Response response = jersey.target(V1_SEARCH + "/project").queryParam("query", "acme").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
    }

    @Test
    void searchComponentTest() {
        Response response = jersey.target(V1_SEARCH + "/component").queryParam("query", "bootstrap").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
    }

    @Test
    void searchServiceComponentTest() {
        Response response = jersey.target(V1_SEARCH + "/service").queryParam("query", "stock-ticker").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
    }

    @Test
    void searchLicenseTest() {
        Response response = jersey.target(V1_SEARCH + "/license").queryParam("query", "Apache").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
    }

    @Test
    void searchVulnerabilityTest() {
        Response response = jersey.target(V1_SEARCH + "/vulnerability").queryParam("query", "CVE-2020").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
    }

    @Test
    void reindexWithBadIndexTypes() {
        Response response = jersey.target(V1_SEARCH + "/reindex").queryParam("type", "BAD_TYPE_1", "BAD_TYPE_2").request()
                .header(X_API_KEY, apiKey)
                .post(null, Response.class);
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("No valid index type was provided", body);
        assertThat(EVENTS).isEmpty();
    }

    @Test
    void reindexWithMixedIndexTypes() {
        Response response = jersey.target(V1_SEARCH + "/reindex").queryParam("type", "BAD_TYPE_1", IndexManager.IndexType.VULNERABILITY.name(), IndexManager.IndexType.LICENSE).request()
                .header(X_API_KEY, apiKey)
                .post(null, Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        String token = json.getString("token");
        Assertions.assertNotNull(token);

        await("Index event dispatch")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(EVENTS).satisfiesExactlyInAnyOrder(
                        event -> {
                            assertThat(event).isInstanceOf(IndexEvent.class);
                            assertThat(((IndexEvent) event).getIndexableClass()).isEqualTo(Vulnerability.class);
                        },
                        event -> {
                            assertThat(event).isInstanceOf(IndexEvent.class);
                            assertThat(((IndexEvent) event).getIndexableClass()).isEqualTo(License.class);
                        }
                ));
    }

}
