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
package org.dependencytrack.vulnanalysis.checkmarx;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.vulnanalysis.api.RetryableVulnAnalysisException;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

final class CheckmarxAccessTokenManager {

    private static final Duration EXPIRY_BUFFER = Duration.ofSeconds(30);
    private static final String CLIENT_ID = "ast-app";
    private static final String GRANT_TYPE = "refresh_token";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ReentrantLock lock = new ReentrantLock();

    private @Nullable String accessToken;
    private @Nullable Instant accessTokenExpiresAt;
    private @Nullable URI authApiBaseUrl;
    private @Nullable String orgId;
    private @Nullable String apiKey;

    CheckmarxAccessTokenManager(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Gets a valid access token, fetching a new one via API Key if necessary.
     *
     * @param authApiBaseUrl the Checkmarx authentication API base URL
     * @param orgId the organization ID
     * @param apiKey the API Key
     * @return a valid access token
     */
    String getAccessToken(URI authApiBaseUrl, String orgId, String apiKey) throws IOException, InterruptedException {
        lock.lockInterruptibly();
        try {
            if (accessToken != null
                    && accessTokenExpiresAt != null
                    && Instant.now().isBefore(accessTokenExpiresAt)
                    && Objects.equals(authApiBaseUrl, this.authApiBaseUrl)
                    && Objects.equals(orgId, this.orgId)
                    && Objects.equals(apiKey, this.apiKey)) {
                return accessToken;
            }

            final var request = HttpRequest.newBuilder()
                    .uri(authApiBaseUrl.resolve("/auth/realms/" + orgId + "/protocol/openid-connect/token"))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(
                            objectMapper.writeValueAsString(new TokenRequest(apiKey))))
                    .build();

            final HttpResponse<InputStream> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            } catch (IOException e) {
                RetryableVulnAnalysisException.throwIfRetryableNetworkError(e, "Checkmarx Auth API request failed");
                throw new UncheckedIOException("Checkmarx Auth API request failed", e);
            }

            if (response.statusCode() != 200) {
                RetryableVulnAnalysisException.throwIfRetryableHttpError(response);
                throw new IOException("Checkmarx Auth API request failed with status " + response.statusCode());
            }

            final var tokenResponse = objectMapper.readValue(response.body(), TokenResponse.class);
            accessToken = tokenResponse.accessToken();
            accessTokenExpiresAt = Instant.now().plusSeconds(tokenResponse.expiresIn()).minus(EXPIRY_BUFFER);
            this.authApiBaseUrl = authApiBaseUrl;
            this.orgId = orgId;
            this.apiKey = apiKey;

            return accessToken;
        } finally {
            lock.unlock();
        }
    }

    private record TokenRequest(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("grant_type") String grantType,
            @JsonProperty("refresh_token") String apiKey) {

        TokenRequest(String apiKey) {
            this(CLIENT_ID, GRANT_TYPE, apiKey);
        }

    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("expires_in") long expiresIn,
            @JsonProperty("refresh_token") String apiKey,
            @JsonProperty("refresh_expires_in") long refreshExpiresIn) {
    }

}



