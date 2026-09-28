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
package org.dependencytrack.auth.workloadidentity;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSetParseException;
import com.nimbusds.jose.jwk.source.JWKSetRetrievalException;
import com.nimbusds.oauth2.sdk.GeneralException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.http.HttpClient;
import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class WorkloadIdentityKeySetFetcherTest {

    @RegisterExtension
    private static final WireMockExtension wireMock =
            WireMockExtension.newInstance().options(options().dynamicPort()).build();

    private static HttpClient httpClient;

    @BeforeAll
    static void beforeAll() {
        httpClient = HttpClient.newHttpClient();
    }

    @AfterAll
    static void afterAll() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @Test
    void fetchKeySetShouldReturnThePublicKeys() throws Exception {
        final RSAKey signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();
        wireMock.stubFor(get(urlPathEqualTo("/keys"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new JWKSet(signingKey.toPublicJWK()).toString())));

        final JWKSet keySet = relaxedFetcher().fetchKeySet(wireMock.baseUrl() + "/keys");
        assertThat(keySet.getKeyByKeyId("key-1")).isNotNull();
    }

    @Test
    void fetchKeySetShouldRejectKeySetWithPrivateKeys() throws Exception {
        final RSAKey signingKey = new RSAKeyGenerator(2048).keyID("key-1").generate();
        wireMock.stubFor(get(urlPathEqualTo("/keys"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new JWKSet(signingKey).toString(/* publicKeysOnly */ false))));

        assertThatExceptionOfType(JWKSetParseException.class)
                .isThrownBy(() -> relaxedFetcher().fetchKeySet(wireMock.baseUrl() + "/keys"))
                .withMessageContaining("public keys");
    }

    @Test
    void fetchKeySetShouldRejectUnreachableUrl() {
        wireMock.stubFor(get(urlPathEqualTo("/keys")).willReturn(aResponse().withStatus(404)));

        assertThatExceptionOfType(JWKSetRetrievalException.class)
                .isThrownBy(() -> relaxedFetcher().fetchKeySet(wireMock.baseUrl() + "/keys"))
                .withMessageContaining("unreachable");
    }

    @Test
    void fetchKeySetShouldRejectResponseExceedingTheSizeLimit() {
        wireMock.stubFor(get(urlPathEqualTo("/keys"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("x".repeat(1024 * 1024 + 1))));

        assertThatExceptionOfType(JWKSetRetrievalException.class)
                .isThrownBy(() -> relaxedFetcher().fetchKeySet(wireMock.baseUrl() + "/keys"))
                .withMessageContaining("larger than 1048576 bytes");
    }

    @Test
    void fetchKeySetShouldGiveUpWhenTheBodyArrivesTooSlowly() throws Exception {
        // WireMock delays the response headers along with the body, which the request timeout already covers.
        try (final var serverSocket = new ServerSocket(0)) {
            Thread.ofVirtual().start(() -> {
                try (final Socket socket = serverSocket.accept()) {
                    socket.getInputStream().read(new byte[4096]);
                    final OutputStream outputStream = socket.getOutputStream();
                    outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n".getBytes(UTF_8));
                    for (int i = 0; i < 50; i++) {
                        outputStream.write(' ');
                        outputStream.flush();
                        Thread.sleep(100);
                    }
                } catch (IOException | InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            final var fetcher =
                    new WorkloadIdentityKeySetFetcher(httpClient, /* relaxedUrlChecks */ true, Duration.ofMillis(500));

            final long startedAtNanos = System.nanoTime();
            assertThatExceptionOfType(JWKSetRetrievalException.class)
                    .isThrownBy(() ->
                            fetcher.fetchKeySet("http://localhost:%d/keys".formatted(serverSocket.getLocalPort())))
                    .withMessageContaining("unreachable");
            assertThat(Duration.ofNanos(System.nanoTime() - startedAtNanos)).isLessThan(Duration.ofSeconds(3));
        }
    }

    @Test
    void fetchKeySetShouldRejectUrlWithUserInfo() {
        assertThatExceptionOfType(JWKSetRetrievalException.class)
                .isThrownBy(() ->
                        new WorkloadIdentityKeySetFetcher(httpClient).fetchKeySet("https://user@example.com/keys"))
                .withMessageContaining("user information");
    }

    @Test
    void resolveJwksUriShouldReturnTheUriFromTheDiscoveryDocument() throws Exception {
        wireMock.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {
                                  "issuer": "%s",
                                  "jwks_uri": "%s/keys"
                                }
                                """.formatted(wireMock.baseUrl(), wireMock.baseUrl()))));

        final String jwksUri = relaxedFetcher().resolveJwksUri(wireMock.baseUrl());
        assertThat(jwksUri).isEqualTo(wireMock.baseUrl() + "/keys");
    }

    @Test
    void resolveJwksUriShouldRejectIssuerMismatch() {
        wireMock.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {
                                  "issuer": "https://evil.example.com",
                                  "jwks_uri": "%s/keys"
                                }
                                """.formatted(wireMock.baseUrl()))));

        assertThatExceptionOfType(GeneralException.class)
                .isThrownBy(() -> relaxedFetcher().resolveJwksUri(wireMock.baseUrl()))
                .withMessageContaining("issuer");
    }

    @Test
    void resolveJwksUriShouldRejectDocumentWithoutJwksUri() {
        wireMock.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {
                                  "issuer": "%s"
                                }
                                """.formatted(wireMock.baseUrl()))));

        assertThatExceptionOfType(GeneralException.class)
                .isThrownBy(() -> relaxedFetcher().resolveJwksUri(wireMock.baseUrl()))
                .withMessageContaining("jwks_uri");
    }

    @Test
    void resolveJwksUriShouldRejectDocumentThatIsNotJsonWithoutEchoingIt() {
        wireMock.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("<html>internal-secret</html>")));

        assertThatExceptionOfType(GeneralException.class)
                .isThrownBy(() -> relaxedFetcher().resolveJwksUri(wireMock.baseUrl()))
                .withMessage("Discovery document is not valid");
    }

    private static WorkloadIdentityKeySetFetcher relaxedFetcher() {
        return new WorkloadIdentityKeySetFetcher(httpClient, /* relaxedUrlChecks */ true, Duration.ofSeconds(10));
    }
}
