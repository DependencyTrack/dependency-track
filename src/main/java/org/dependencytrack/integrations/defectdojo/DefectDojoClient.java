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
package org.dependencytrack.integrations.defectdojo;

import alpine.logging.Logger;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.UnirestInstance;
import org.dependencytrack.common.UnirestFactory;
import java.io.InputStream;
import java.net.URL;
import java.util.Date;
import java.text.SimpleDateFormat;

public class DefectDojoClient {

    private static final Logger LOGGER = Logger.getLogger(DefectDojoClient.class);
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private final DefectDojoUploader uploader;
    private final URL baseURL;

    public DefectDojoClient(final DefectDojoUploader uploader, final URL baseURL) {
        this.uploader = uploader;
        this.baseURL = baseURL;
    }

    public void uploadDependencyTrackFindings(final String token, final String engagementId, final InputStream findingsJson) {
        LOGGER.debug("Uploading Dependency-Track findings to DefectDojo");
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HttpRequestWithBody request = ui.post(baseURL + "/api/v2/import-scan/");

        final HttpResponse<String> response = request
                .header("accept", "application/json")
                .header("Authorization", "Token " + token)
                .field("file", findingsJson, "findings.json")
                .field("engagement", engagementId)
                .field("scan_type", "Dependency Track Finding Packaging Format (FPF) Export")
                .field("verified", "true")
                .field("active", "true")
                .field("minimum_severity", "Info")
                .field("close_old_findings", "true")
                .field("push_to_jira", "false")
                .field("scan_date", DATE_FORMAT.format(new Date()))
                .asString();
        if (response.getStatus() == 201) {
            LOGGER.debug("Successfully uploaded findings to DefectDojo");
        } else {
            LOGGER.warn("DefectDojo Client did not receive expected response while attempting to upload "
                    + "Dependency-Track findings. HTTP response code: "
                    + response.getStatus() + " - " + response.getStatusText());
            uploader.handleUnexpectedHttpResponse(LOGGER, request.getUrl(), response.getStatus(), response.getStatusText());
        }
    }
}
