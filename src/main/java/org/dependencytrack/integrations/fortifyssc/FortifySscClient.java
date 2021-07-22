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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.integrations.fortifyssc;

import alpine.logging.Logger;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestInstance;
import kong.unirest.json.JSONObject;
import org.dependencytrack.common.UnirestFactory;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;

public class FortifySscClient {

    private static final Logger LOGGER = Logger.getLogger(FortifySscClient.class);
    private final FortifySscUploader uploader;
    private final URL baseURL;

    public FortifySscClient(final FortifySscUploader uploader, final URL baseURL) {
        this.uploader = uploader;
        this.baseURL = baseURL;
    }

    public String generateOneTimeUploadToken(final String citoken) {
        LOGGER.debug("Generating one-time upload token");
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final JSONObject payload = new JSONObject().put("fileTokenType", "UPLOAD");
        final HttpRequestWithBody request = ui.post(baseURL + "/api/v1/fileTokens");
        final HttpResponse<JsonNode> response = request
                .header("Content-Type", "application/json")
                .header("Authorization", "FortifyToken " + Base64.getEncoder().encodeToString(citoken.getBytes(StandardCharsets.UTF_8)))
                .body(payload)
                .asJson();
        if (response.getStatus() == 201) {
            if (response.getBody() != null) {
                final JSONObject root = response.getBody().getObject();
                LOGGER.debug("One-time upload token retrieved");
                return root.getJSONObject("data").getString("token");
            }
        } else {
            LOGGER.warn("Fortify SSC Client did not receive expected response while attempting to generate a "
                    + "one-time-use fileupload token. HTTP response code: "
                    + response.getStatus() + " - " + response.getStatusText());
            uploader.handleUnexpectedHttpResponse(LOGGER, request.getUrl(), response.getStatus(), response.getStatusText());
        }
        return null;
    }

    public void uploadDependencyTrackFindings(final String token, final String applicationVersion, final InputStream findingsJson) {
        LOGGER.debug("Uploading Dependency-Track findings to Fortify SSC");
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HashMap<String, Object> params = new HashMap<>();
        params.put("engineType", "DEPENDENCY_TRACK");
        params.put("mat", token);
        params.put("entityId", applicationVersion);
        final HttpRequestWithBody request = ui.post(baseURL + "/upload/resultFileUpload.html");
        final HttpResponse<String> response = request
                .header("accept", "application/xml")
                .queryString(params)
                .field("files[]", findingsJson, "findings.json")
                .asString();
        if (response.getStatus() == 200) {
            LOGGER.debug("Successfully uploaded findings to Fortify SSC");
        } else {
            LOGGER.warn("Fortify SSC Client did not receive expected response while attempting to upload "
                    + "Dependency-Track findings. HTTP response code: "
                    + response.getStatus() + " - " + response.getStatusText());
            uploader.handleUnexpectedHttpResponse(LOGGER, request.getUrl(), response.getStatus(), response.getStatusText());
        }
    }
}
