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
package org.dependencytrack.integrations.defectdojo;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class DefectDojoClientTest {

    private HttpServer server;
    private HttpClient httpClient;
    private AtomicReference<String> capturedBody;

    @BeforeEach
    void setUp() throws IOException {
        capturedBody = new AtomicReference<>("");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v2/import-scan/", exchange -> {
            byte[] bytes = exchange.getRequestBody().readAllBytes();
            capturedBody.set(new String(bytes, StandardCharsets.UTF_8));
            byte[] resp = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(201, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });
        server.start();
        httpClient = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        if (httpClient != null) {
            httpClient.close();
        }
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void testUploadDependencyTrackFindingsClosesOldFindingsByDefault() throws Exception {
        DefectDojoClient client = new DefectDojoClient(
                httpClient,
                mock(DefectDojoUploader.class),
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()).toURL());

        client.uploadDependencyTrackFindings(
                "token",
                "123",
                new ByteArrayInputStream("{}".getBytes(StandardCharsets.UTF_8)),
                true,
                "project-a",
                null);

        assertTrue(capturedBody.get().contains("name=\"close_old_findings\"\r\n\r\ntrue\r\n"));
    }

    @Test
    void testUploadDependencyTrackFindingsRespectsCloseOldFindingsFalse() throws Exception {
        DefectDojoClient client = new DefectDojoClient(
                httpClient,
                mock(DefectDojoUploader.class),
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()).toURL());

        client.uploadDependencyTrackFindings(
                "token",
                "123",
                new ByteArrayInputStream("{}".getBytes(StandardCharsets.UTF_8)),
                true,
                "project-b",
                null,
                false);

        assertTrue(capturedBody.get().contains("name=\"close_old_findings\"\r\n\r\nfalse\r\n"));
    }
}
