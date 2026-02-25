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
package org.dependencytrack.tasks.repositories;

import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import java.text.SimpleDateFormat;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

class PypiMetaAnalyzerTest {

    private static ClientAndServer mockServer;

    @BeforeAll
    static void beforeAll() {
        mockServer = ClientAndServer.startClientAndServer(0);
    }

    @AfterAll
    static void afterAll() {
        mockServer.stop();
    }

    @BeforeEach
    void beforeEach() {
        mockServer.reset();
    }

    @Test
    void testAnalyzerJsonPrefersNonYankedAndSetsUploadTime() throws Exception {
        final Component component = new Component();
        component.setPurl(new PackageURL("pkg:pypi/Example_Pkg@0.0.1"));

        final PypiMetaAnalyzer analyzer = new PypiMetaAnalyzer();
        analyzer.setRepositoryId("1");
        analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));

        Assertions.assertTrue(analyzer.isApplicable(component));
        Assertions.assertEquals(RepositoryType.PYPI, analyzer.supportedRepositoryType());

        final String body = "{" +
                "\"meta\":{\"api-version\":\"1.1\"}," +
                "\"name\":\"example-pkg\"," +
                "\"versions\":[\"1.0.0\",\"2.0.0\",\"2.1.0\"]," +
                "\"files\":[" +
                "{\"filename\":\"example_pkg-1.0.0.tar.gz\",\"yanked\":false,\"upload-time\":\"2023-01-01T10:00:00Z\"}," +
                "{\"filename\":\"example_pkg-2.0.0.tar.gz\",\"yanked\":true,\"upload-time\":\"2024-01-01T10:00:00Z\"}," +
                "{\"filename\":\"example_pkg-2.1.0.tar.gz\",\"yanked\":false,\"upload-time\":\"2025-01-01T10:00:00Z\"}" +
                "]" +
                "}";

        @SuppressWarnings("resource")
        final MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
        mockClient.when(
                        request()
                                .withMethod("GET")
                                // PEP 503 normalization: Example_Pkg -> example-pkg
                                .withPath("/simple/example-pkg/")
                                .withHeader(HttpHeaders.ACCEPT)
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
                                .withBody(body)
                );

        final MetaModel meta = analyzer.analyze(component);
        Assertions.assertEquals("2.1.0", meta.getLatestVersion());
        Assertions.assertEquals(
                new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX").parse("2025-01-01T10:00:00Z"),
                meta.getPublishedTimestamp());
    }

    @Test
    void testAnalyzerJsonAllYankedStillReturnsLatestVersion() throws Exception {
        final Component component = new Component();
        component.setPurl(new PackageURL("pkg:pypi/example-pkg@0.0.1"));

        final PypiMetaAnalyzer analyzer = new PypiMetaAnalyzer();
        analyzer.setRepositoryId("1");
        analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));

        final String body = "{" +
                "\"meta\":{\"api-version\":\"1.1\"}," +
                "\"name\":\"example-pkg\"," +
                "\"versions\":[\"1.0.0\",\"2.0.0\"]," +
                "\"files\":[" +
                "{\"filename\":\"example_pkg-1.0.0.tar.gz\",\"yanked\":true}," +
                "{\"filename\":\"example_pkg-2.0.0.tar.gz\",\"yanked\":true}" +
                "]" +
                "}";

        @SuppressWarnings("resource")
        final MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
        mockClient.when(
                        request()
                                .withMethod("GET")
                                .withPath("/simple/example-pkg/")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
                                .withBody(body)
                );

        final MetaModel meta = analyzer.analyze(component);
        Assertions.assertEquals("2.0.0", meta.getLatestVersion());
        Assertions.assertNull(meta.getPublishedTimestamp());
    }

    @Test
    void testAnalyzerHtmlPrefersNonYankedAndLeavesTimestampNull() throws Exception {
        final Component component = new Component();
        component.setPurl(new PackageURL("pkg:pypi/example-pkg@0.0.1"));

        final PypiMetaAnalyzer analyzer = new PypiMetaAnalyzer();
        analyzer.setRepositoryId("1");
        analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));

        final String html = "<html><body>" +
                "<a href=\"/packages/example_pkg-1.0.0.tar.gz\">example_pkg-1.0.0.tar.gz</a>" +
                "<a href=\"/packages/example_pkg-2.0.0.tar.gz\" data-yanked>example_pkg-2.0.0.tar.gz</a>" +
                "<a href=\"/packages/example_pkg-2.1.0.tar.gz\">example_pkg-2.1.0.tar.gz</a>" +
                "</body></html>";

        @SuppressWarnings("resource")
        final MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
        mockClient.when(
                        request()
                                .withMethod("GET")
                                .withPath("/simple/example-pkg/")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "text/html; charset=utf-8")
                                .withBody(html)
                );

        final MetaModel meta = analyzer.analyze(component);
        Assertions.assertEquals("2.1.0", meta.getLatestVersion());
        Assertions.assertNull(meta.getPublishedTimestamp());
    }
}

