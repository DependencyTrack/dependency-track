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

import alpine.common.logging.Logger;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

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
        var request = new HttpPost(baseURL + "/api/v1/fileTokens");
        final JSONObject payload = new JSONObject().put("fileTokenType", "UPLOAD");
        request.addHeader("Content-Type", "application/json");
        request.addHeader("Authorization", "FortifyToken " + Base64.getEncoder().encodeToString(citoken.getBytes(StandardCharsets.UTF_8)));
        try {
            request.setEntity(new StringEntity(payload.toString()));
            try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
                    if (response.getEntity() != null) {
                        String responseString = EntityUtils.toString(response.getEntity());
                        final JSONObject root = new JSONObject(responseString);
                        LOGGER.debug("One-time upload token retrieved");
                        return root.getJSONObject("data").getString("token");
                    }
                } else {
                    uploader.handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
                }
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        }
        return null;
    }

    public void uploadDependencyTrackFindings(final String token, final String applicationVersion, final InputStream findingsJson) {
        try {
            LOGGER.debug("Uploading Dependency-Track findings to Fortify SSC");
            var builder = new URIBuilder(baseURL + "/upload/resultFileUpload.html");
            builder.setParameter("engineType", "DEPENDENCY_TRACK").setParameter("mat", token).setParameter("entityId", applicationVersion);
            HttpPost request = new HttpPost(builder.build());
            request.addHeader("accept", "application/xml");
            HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                    .addBinaryBody("files[]", findingsJson, ContentType.APPLICATION_OCTET_STREAM, "findings.json")
                    .build();
            request.setEntity(data);
            try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    LOGGER.debug("Successfully uploaded findings to Fortify SSC");
                } else {
                    uploader.handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
                }
            }
        } catch (URISyntaxException | IOException ex) {
            uploader.handleException(LOGGER, ex);
        }
    }
}