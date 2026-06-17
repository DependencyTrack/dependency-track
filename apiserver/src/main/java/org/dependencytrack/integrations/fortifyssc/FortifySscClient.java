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
package org.dependencytrack.integrations.fortifyssc;

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.common.MultipartBodyPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class FortifySscClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(FortifySscClient.class);

    private final HttpClient httpClient;
    private final FortifySscUploader uploader;
    private final URL baseURL;

    FortifySscClient(
            HttpClient httpClient,
            FortifySscUploader uploader,
            URL baseURL) {
        this.httpClient = httpClient;
        this.uploader = uploader;
        this.baseURL = baseURL;
    }

    public String generateOneTimeUploadToken(final String citoken) {
        LOGGER.debug("Generating one-time upload token");
        final String payload = Mappers.jsonMapper().createObjectNode().put("fileTokenType", "UPLOAD").toString();

        final var request = HttpRequest.newBuilder()
                .uri(URI.create(baseURL + "/api/v1/fileTokens"))
                .header("Content-Type", "application/json")
                .header("Authorization", "FortifyToken " + Base64.getEncoder().encodeToString(citoken.getBytes(StandardCharsets.UTF_8)))
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        try {
            final HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 201 && response.body() != null) {
                final JsonNode root = Mappers.jsonMapper().readTree(response.body());
                LOGGER.debug("One-time upload token retrieved");
                return root.get("data").get("token").asText();
            } else {
                uploader.handleUnexpectedHttpResponse(LOGGER, request.uri().toString(), response.statusCode(), response.body());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            uploader.handleException(LOGGER, ex);
        }
        return null;
    }

    public void uploadDependencyTrackFindings(final String token, final String applicationVersion, final InputStream findingsJson) {
        LOGGER.debug("Uploading Dependency-Track findings to Fortify SSC");

        final String uri = "%s/upload/resultFileUpload.html?engineType=DEPENDENCY_TRACK&mat=%s&entityId=%s"
                .formatted(baseURL, token, applicationVersion);

        final var multipart = new MultipartBodyPublisher()
                .addFilePart("files[]", "findings.json", findingsJson, "application/octet-stream");

        final var request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Accept", "application/xml")
                .header("Content-Type", multipart.contentType())
                .POST(multipart.build())
                .build();

        try {
            final HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                LOGGER.debug("Successfully uploaded findings to Fortify SSC");
            } else {
                uploader.handleUnexpectedHttpResponse(LOGGER, request.uri().toString(), response.statusCode(), response.body());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            uploader.handleException(LOGGER, ex);
        }
    }
}
