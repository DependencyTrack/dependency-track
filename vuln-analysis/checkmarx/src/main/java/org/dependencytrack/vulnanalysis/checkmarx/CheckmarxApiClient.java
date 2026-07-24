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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Client for Checkmarx vulnerability API.
 */
final class CheckmarxApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CheckmarxApiClient.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final CheckmarxAccessTokenManager tokenManager;
    private final String refreshToken;
    private final String orgId;
    private final URI authApiBaseUrl;
    private final URI apiBaseUrl;

    CheckmarxApiClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            CheckmarxAccessTokenManager tokenManager,
            String refreshToken,
            String orgId,
            URI authApiBaseUrl,
            URI apiBaseUrl) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.tokenManager = tokenManager;
        this.refreshToken = refreshToken;
        this.orgId = orgId;
        this.authApiBaseUrl = authApiBaseUrl;
        this.apiBaseUrl = apiBaseUrl;
    }

    /**
     * Fetches vulnerabilities for a batch of PURLs.
     *
     * @param purls the package URLs to analyze
     * @return vulnerabilities response from Checkmarx API
     */
    CheckmarxApiResponse fetchVulnerabilities(Collection<String> purls) throws IOException, InterruptedException {
        if (purls.isEmpty()) {
            return new CheckmarxApiResponse(List.of());
        }

        LOGGER.debug("Fetching Checkmarx vulnerabilities for {} PURLs", purls.size());

        final URI requestUrl = apiBaseUrl.resolve("/api/sca/packages/vulnerabilities"
                                + "?IncludeRiskDetails=true" + "&IncludeVersionDetails=true" + "&IncludeVersionRemediation=true");

        // Ensure valid access token (will be cached if still valid)
        final String accessToken = tokenManager.getAccessToken(authApiBaseUrl, orgId, refreshToken);

        final String requestBody = objectMapper.writeValueAsString(new VulnerabilityRequest(new ArrayList<>(purls)));

        final var request = HttpRequest.newBuilder()
                .uri(requestUrl)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        final HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());

        try (final InputStream body = response.body()) {
            if (response.statusCode() == 200) {
                return objectMapper.readValue(body, CheckmarxApiResponse.class);
            }

            body.transferTo(OutputStream.nullOutputStream());

            if (response.statusCode() == 404) {
                LOGGER.debug("No vulnerabilities found for provided PURLs");
                return new CheckmarxApiResponse(List.of());
            }

            throw new IOException("Checkmarx API request failed with status " + response.statusCode());
        }
    }

    private record VulnerabilityRequest(List<String> packageUrls) {
    }

}

