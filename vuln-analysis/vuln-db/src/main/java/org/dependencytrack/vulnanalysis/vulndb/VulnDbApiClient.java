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
import org.dependencytrack.vulnanalysis.api.RetryableVulnAnalysisException;
import org.dependencytrack.vulnanalysis.vulndb.VulnDbApiResponse.PaginatedResponse;
import org.dependencytrack.vulnanalysis.vulndb.VulnDbApiResponse.Vulnerability;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * @since 5.0.0
 */
final class VulnDbApiClient {

    private static final int PAGE_SIZE = 100;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final VulnDbAccessTokenManager tokenManager;
    private final String clientId;
    private final String clientSecret;
    private final URI apiBaseUrl;

    VulnDbApiClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            VulnDbAccessTokenManager tokenManager,
            String clientId,
            String clientSecret,
            URI apiBaseUrl) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.tokenManager = tokenManager;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.apiBaseUrl = apiBaseUrl;
    }

    List<Vulnerability> getVulnerabilitiesByCpe(String cpe) throws IOException, InterruptedException {
        final var allVulnerabilities = new ArrayList<Vulnerability>();
        int page = 1;

        while (true) {
            final var uri = URI.create(
                    apiBaseUrl + "/api/v1/vulnerabilities/find_by_cpe"
                            + "?cpe=" + URLEncoder.encode(cpe, StandardCharsets.UTF_8)
                            + "&size=" + PAGE_SIZE
                            + "&page=" + page);

            final String accessToken = tokenManager.getAccessToken(apiBaseUrl, clientId, clientSecret);

            final var request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + accessToken)
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            final HttpResponse<InputStream> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());

            try (final InputStream body = response.body()) {
                if (response.statusCode() == 200) {
                    final var paginatedResponse = objectMapper.readValue(body, PaginatedResponse.class);
                    if (paginatedResponse.results() != null) {
                        allVulnerabilities.addAll(paginatedResponse.results());
                    }

                    final int totalEntries = paginatedResponse.totalEntries();
                    if (page * PAGE_SIZE >= totalEntries) {
                        break;
                    }

                    page++;
                    continue;
                }

                body.transferTo(OutputStream.nullOutputStream());

                if (response.statusCode() == 404) {
                    return List.of();
                }

                RetryableVulnAnalysisException.throwIfRetryableHttpError(response);
                throw new IOException("VulnDB API request failed with status " + response.statusCode());
            }
        }

        return allVulnerabilities;
    }

}
