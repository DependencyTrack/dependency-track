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

import alpine.common.logging.Logger;
import kong.unirest.UnirestInstance;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.dependencytrack.common.UnirestFactory;

import java.io.InputStream;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class DefectDojoClient {

    private static final Logger LOGGER = Logger.getLogger(DefectDojoClient.class);
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private final DefectDojoUploader uploader;
    private final URL baseURL;

    public DefectDojoClient(final DefectDojoUploader uploader,  final URL baseURL) {
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

    // Pulling DefectDojo 'tests' API endpoint with engagementID filter on, and retrieve a list of existing tests
    public ArrayList getDojoTestIds(final String token, final String eid) {
        LOGGER.debug("Pulling DefectDojo Tests API ...");
        String tests_uri = "/api/v2/tests/";
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        LOGGER.debug("Make the first pagination call");
        HttpResponse<JsonNode> response = ui.get(baseURL + tests_uri + "?limit=100&engagement=" + eid)
                .header("accept", "application/json")
                .header("Authorization", "Token " + token)
                .asJson();
        if (response.getStatus() == 200) {
            if (response.getBody() != null && response.getBody().getObject() != null) {
                JsonNode root = response.getBody();
                JSONObject dojoObj = root.getObject();
                JSONArray dojoArray = dojoObj.getJSONArray("results");
                ArrayList dojoTests = jsonToList(dojoArray);
                String nextUrl = "";
                while (dojoObj.get("next") != null ) {
                    LOGGER.error("Make the subsequent pagination call on " + dojoObj.get("next"));
                    nextUrl = dojoObj.get("next").toString();
                    LOGGER.debug("Make the subsequent pagination call on " + nextUrl);
                    response = ui.get(nextUrl)
                            .header("accept", "application/json")
                            .header("Authorization", "Token " + token)
                            .asJson();
                    nextUrl = dojoObj.get("next").toString();
                    root = response.getBody();
                    dojoObj = root.getObject();
                    dojoArray = dojoObj.getJSONArray("results");
                    dojoTests.addAll(jsonToList(dojoArray));
                }
                LOGGER.debug("Successfully retrieve the test list ");
                return dojoTests;
            }
        } else {
            LOGGER.warn("DefectDojo Client did not receive expected response while attempting to retrieve tests list "
                    + response.getStatus() + " - " + response.getBody());
        }
        return null;
    }

    // Given the engagement id and scan type, search for existing test id
    public String getDojoTestId(final String engagementID,  final ArrayList dojoTests) {
        for (int i = 0; i < dojoTests.size(); i++) {
            String s = dojoTests.get(i).toString();
            JSONObject dojoTest = new JSONObject(s);
            if (dojoTest.get("engagement").toString().equals(engagementID)  &&
                dojoTest.get("scan_type").toString().equals("Dependency Track Finding Packaging Format (FPF) Export")) {
                return dojoTest.get("id").toString();
            }
        }
        return "";
    }

    // JSONArray to ArrayList simple converter
    public ArrayList<String> jsonToList(final JSONArray jsonArray) {
        ArrayList<String> list = new ArrayList<String>();
        if (jsonArray != null) {
            for (int i = 0; i < jsonArray.length(); i++) {
                list.add(jsonArray.get(i).toString());
            }
        }
        return list;
    }

    /*
     * A Reimport will reuse (overwrite) the existing test, instead of create a new test.
     * The Successfully reimport will also  increase the reimport counter by 1.
    */
    public void reimportDependencyTrackFindings(final String token, final String engagementId, final InputStream findingsJson, final String testId) {
        LOGGER.debug("Re-reimport Dependency-Track findings to DefectDojo per Engagement");
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HttpRequestWithBody request = ui.post(baseURL + "/api/v2/reimport-scan/");
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
                .field("test", testId)
                .field("scan_date", DATE_FORMAT.format(new Date()))
                .asString();
        if (response.getStatus() == 201) {
            LOGGER.debug("Successfully reimport findings to DefectDojo");
        } else {
            LOGGER.warn("DefectDojo Client did not receive expected response while attempting to reimport"
                    + "Dependency-Track findings. HTTP response code: "
                    + response.getStatus() + " - " + response.getStatusText());
            uploader.handleUnexpectedHttpResponse(LOGGER, request.getUrl(), response.getStatus(), response.getBody());
        }
    }

}
