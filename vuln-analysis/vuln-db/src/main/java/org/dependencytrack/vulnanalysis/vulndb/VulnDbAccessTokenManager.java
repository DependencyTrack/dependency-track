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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @since 5.0.0
 */
final class VulnDbAccessTokenManager {

    private static final Duration EXPIRY_BUFFER = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ReentrantLock lock = new ReentrantLock();

    private @Nullable String accessToken;
    private @Nullable Instant expiresAt;
    private @Nullable String clientId;
    private @Nullable String clientSecret;
    private @Nullable URI tokenEndpoint;

    VulnDbAccessTokenManager(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    String getAccessToken(
            URI apiBaseUrl,
            String clientId,
            String clientSecret) throws IOException, InterruptedException {
        final URI tokenEndpoint = apiBaseUrl.resolve("/oauth/token");

        lock.lockInterruptibly();
        try {
            if (accessToken != null
                    && expiresAt != null
                    && Instant.now().isBefore(expiresAt)
                    && Objects.equals(tokenEndpoint, this.tokenEndpoint)
                    && Objects.equals(clientId, this.clientId)
                    && Objects.equals(clientSecret, this.clientSecret)) {
                return accessToken;
            }

            final var request = HttpRequest.newBuilder()
                    .uri(tokenEndpoint)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString(
                            objectMapper.writeValueAsString(new TokenRequest(clientId, clientSecret))))
                    .build();

            final HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                throw new IOException("OAuth2 token request failed with status " + response.statusCode());
            }

            final var tokenResponse = objectMapper.readValue(response.body(), TokenResponse.class);
            accessToken = tokenResponse.accessToken();
            expiresAt = Instant.now().plusSeconds(tokenResponse.expiresIn()).minus(EXPIRY_BUFFER);
            this.tokenEndpoint = tokenEndpoint;
            this.clientId = clientId;
            this.clientSecret = clientSecret;

            return accessToken;
        } finally {
            lock.unlock();
        }
    }

    private record TokenRequest(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("client_secret") String clientSecret,
            @JsonProperty("grant_type") String grantType) {

        TokenRequest(String clientId, String clientSecret) {
            this(clientId, clientSecret, "client_credentials");
        }

    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("expires_in") long expiresIn) {
    }

}
