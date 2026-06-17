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
package org.dependencytrack.vulnanalysis.vulndb;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class VulnDbAccessTokenManagerTest {

    private VulnDbAccessTokenManager tokenManager;
    private URI apiBaseUrl;

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        apiBaseUrl = URI.create(wmRuntimeInfo.getHttpBaseUrl());
        tokenManager = new VulnDbAccessTokenManager(
                HttpClient.newHttpClient(),
                new ObjectMapper());
    }

    @Test
    void shouldAcquireToken() throws Exception {
        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "tok-123", "token_type": "Bearer", "expires_in": 3600}
                                """)));

        final String token = tokenManager.getAccessToken(apiBaseUrl, "client-id", "client-secret");
        assertThat(token).isEqualTo("tok-123");
    }

    @Test
    void shouldCacheToken() throws Exception {
        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "tok-cached", "token_type": "Bearer", "expires_in": 3600}
                                """)));

        final String token1 = tokenManager.getAccessToken(apiBaseUrl, "client-id", "client-secret");
        final String token2 = tokenManager.getAccessToken(apiBaseUrl, "client-id", "client-secret");

        assertThat(token1).isEqualTo("tok-cached");
        assertThat(token2).isEqualTo("tok-cached");
        verify(1, postRequestedFor(urlPathEqualTo("/oauth/token")));
    }

    @Test
    void shouldRefreshExpiredToken() throws Exception {
        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "tok-expired", "token_type": "Bearer", "expires_in": 0}
                                """)));

        tokenManager.getAccessToken(apiBaseUrl, "client-id", "client-secret");

        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "tok-refreshed", "token_type": "Bearer", "expires_in": 3600}
                                """)));

        final String token = tokenManager.getAccessToken(apiBaseUrl, "client-id", "client-secret");
        assertThat(token).isEqualTo("tok-refreshed");
        verify(2, postRequestedFor(urlPathEqualTo("/oauth/token")));
    }

    @Test
    void shouldInvalidateOnCredentialChange() throws Exception {
        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "tok-old", "token_type": "Bearer", "expires_in": 3600}
                                """)));

        tokenManager.getAccessToken(apiBaseUrl, "client-id-1", "secret-1");

        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(/* language=JSON */ """
                                {"access_token": "tok-new", "token_type": "Bearer", "expires_in": 3600}
                                """)));

        final String token = tokenManager.getAccessToken(apiBaseUrl, "client-id-2", "secret-2");
        assertThat(token).isEqualTo("tok-new");
        verify(2, postRequestedFor(urlPathEqualTo("/oauth/token")));
    }

    @Test
    void shouldThrowOnTokenEndpointError() {
        stubFor(post(urlPathEqualTo("/oauth/token"))
                .willReturn(aResponse()
                        .withStatus(401)
                        .withBody("Unauthorized")));

        assertThatThrownBy(() -> tokenManager.getAccessToken(apiBaseUrl, "bad-id", "bad-secret"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("401");
    }

}
