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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked")
class DefectDojoClientTest {

    private HttpClient httpClient;
    private DefectDojoClient client;

    @BeforeEach
    void setUp() throws Exception {
        httpClient = mock(HttpClient.class);
        client = new DefectDojoClient(
                httpClient,
                mock(DefectDojoUploader.class),
                URI.create("http://localhost:12345").toURL());
    }

    private HttpResponse<String> response(int status, String body) {
        return new HttpResponse<>() {
            @Override
            public int statusCode() {
                return status;
            }

            @Override
            public String body() {
                return body;
            }

            @Override
            public HttpRequest request() {
                return HttpRequest.newBuilder(URI.create("http://localhost:12345"))
                        .build();
            }

            @Override
            public java.util.Optional<HttpResponse<String>> previousResponse() {
                return java.util.Optional.empty();
            }

            @Override
            public java.net.http.HttpHeaders headers() {
                return java.net.http.HttpHeaders.of(java.util.Map.of(), (name, value) -> true);
            }

            @Override
            public java.util.Optional<javax.net.ssl.SSLSession> sslSession() {
                return java.util.Optional.empty();
            }

            @Override
            public URI uri() {
                return URI.create("http://localhost:12345");
            }

            @Override
            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_1_1;
            }
        };
    }

    @Test
    void testSuccessfulEmptyLookup() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "{\"results\":[],\"next\":null}"));

        assertTrue(client.getDojoTestIds("test-token", "12345").isEmpty());
        verify(httpClient).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testSuccessfulPagination() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    assertEquals("GET", request.method());
                    assertEquals(
                            "Token test-token",
                            request.headers().firstValue("Authorization").orElseThrow());
                    if (request.uri().getQuery().equals("limit=100&engagement=12345")) {
                        return response(200, """
                                {"results":[{"id":7}],
                                 "next":"http://localhost:12345/api/v2/tests/?limit=100&engagement=12345&offset=100"}
                                """);
                    }
                    assertEquals(
                            "limit=100&engagement=12345&offset=100",
                            request.uri().getQuery());
                    return response(200, "{\"results\":[{\"id\":8}],\"next\":null}");
                });

        var tests = client.getDojoTestIds("test-token", "12345");

        assertEquals(java.util.List.of("{\"id\":7}", "{\"id\":8}"), tests);
        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testHttpFailureOnFirstPage() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(503, "{\"detail\":\"Service unavailable\"}"));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
        verify(httpClient).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testHttpFailureOnSecondPageDoesNotReturnPartialResults() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, """
                                {"results":[{"id":7}],
                                 "next":"http://localhost:12345/api/v2/tests/?offset=100"}
                                """), response(503, "{\"detail\":\"Service unavailable\"}"));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testNetworkFailure() throws Exception {
        IOException failure = new IOException("Simulated network failure");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(failure);

        var thrown = assertThrows(UncheckedIOException.class, () -> client.getDojoTestIds("test-token", "12345"));

        assertSame(failure, thrown.getCause());
    }

    @Test
    void testNetworkFailureOnSecondPageDoesNotReturnPartialResults() throws Exception {
        IOException failure = new IOException("Simulated second-page failure");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, """
                        {"results":[{"id":7}],
                         "next":"http://localhost:12345/api/v2/tests/?offset=100"}
                        """))
                .thenThrow(failure);

        var thrown = assertThrows(UncheckedIOException.class, () -> client.getDojoTestIds("test-token", "12345"));

        assertSame(failure, thrown.getCause());
        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testInvalidJson() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "{invalid"));

        assertThrows(UncheckedIOException.class, () -> client.getDojoTestIds("test-token", "12345"));
    }

    @Test
    void testNullBody() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, null));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
    }

    @Test
    void testBlankBody() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "   "));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
    }

    @Test
    void testMissingResultsArray() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "{\"next\":null}"));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
    }

    @Test
    void testInvalidResultsType() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "{\"results\":{},\"next\":null}"));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
    }

    @Test
    void testInvalidNextPageType() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "{\"results\":[],\"next\":123}"));

        assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
    }

    @Test
    void testInterruptionPreservesInterruptFlag() throws Exception {
        assertFalse(Thread.currentThread().isInterrupted());
        InterruptedException failure = new InterruptedException("Simulated interruption");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(failure);

        try {
            var thrown = assertThrows(IllegalStateException.class, () -> client.getDojoTestIds("test-token", "12345"));
            assertSame(failure, thrown.getCause());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }
}
