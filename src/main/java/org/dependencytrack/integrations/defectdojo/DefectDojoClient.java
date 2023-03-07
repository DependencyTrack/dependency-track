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
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

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
        HttpPost request = new HttpPost(baseURL + "/api/v2/import-scan/");
        InputStreamBody inputStreamBody = new InputStreamBody(findingsJson, ContentType.APPLICATION_OCTET_STREAM, "findings.json");
        request.addHeader("accept", "application/json");
        request.addHeader("Authorization", "Token " + token);
        HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addPart("file", inputStreamBody)
                .addPart("engagement", new StringBody(engagementId, ContentType.MULTIPART_FORM_DATA))
                .addPart("scan_type", new StringBody("Dependency Track Finding Packaging Format (FPF) Export", ContentType.MULTIPART_FORM_DATA))
                .addPart("verified", new StringBody("true", ContentType.MULTIPART_FORM_DATA))
                .addPart("active", new StringBody("true", ContentType.MULTIPART_FORM_DATA))
                .addPart("minimum_severity", new StringBody("Info", ContentType.MULTIPART_FORM_DATA))
                .addPart("close_old_findings", new StringBody("true", ContentType.MULTIPART_FORM_DATA))
                .addPart("push_to_jira", new StringBody("push_to_jira", ContentType.MULTIPART_FORM_DATA))
                .addPart("scan_date", new StringBody(DATE_FORMAT.format(new Date()), ContentType.MULTIPART_FORM_DATA))
                .build();
        request.setEntity(data);


        try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
                LOGGER.debug("Successfully uploaded findings to DefectDojo");
            } else {
                uploader.handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        }
    }

    // Pulling DefectDojo 'tests' API endpoint with engagementID filter on, and retrieve a list of existing tests
    public ArrayList getDojoTestIds(final String token, final String eid) {
        LOGGER.debug("Pulling DefectDojo Tests API ...");
        String testsUri = "/api/v2/tests/";
        LOGGER.debug("Make the first pagination call");
        try {
            URIBuilder uriBuilder = new URIBuilder(baseURL + testsUri);
            uriBuilder.addParameter("limit", "100");
            uriBuilder.addParameter("engagement", eid);
            HttpGet request = new HttpGet(uriBuilder.build().toString());
            request.addHeader("accept", "application/json");
            request.addHeader("Authorization", "Token " + token);
            try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    if (response.getEntity() != null) {
                        String stringResponse = EntityUtils.toString(response.getEntity());
                        JSONObject dojoObj = new JSONObject(stringResponse);
                        JSONArray dojoArray = dojoObj.getJSONArray("results");
                        ArrayList dojoTests = jsonToList(dojoArray);
                        String nextUrl = "";
                        while (dojoObj.get("next") != null) {
                            nextUrl = dojoObj.get("next").toString();
                            LOGGER.debug("Making the subsequent pagination call on " + nextUrl);
                            uriBuilder = new URIBuilder(nextUrl);
                            request = new HttpGet(uriBuilder.build().toString());
                            request.addHeader("accept", "application/json");
                            request.addHeader("Authorization", "Token " + token);
                            try (CloseableHttpResponse response1 = HttpClientPool.getClient().execute(request)) {
                                nextUrl = dojoObj.get("next").toString();
                                stringResponse = EntityUtils.toString(response1.getEntity());
                            }
                            dojoObj = new JSONObject(stringResponse);
                            dojoArray = dojoObj.getJSONArray("results");
                            dojoTests.addAll(jsonToList(dojoArray));
                        }
                        LOGGER.debug("Successfully retrieved the test list ");
                        return dojoTests;
                    }
                } else {
                    LOGGER.warn("DefectDojo Client did not receive expected response while attempting to retrieve tests list "
                            + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
                }
            }
        } catch (IOException | URISyntaxException ex) {
            uploader.handleException(LOGGER, ex);
        }
        return new ArrayList<>();
    }

    // Given the engagement id and scan type, search for existing test id
    public String getDojoTestId(final String engagementID, final ArrayList dojoTests) {
        for (int i = 0; i < dojoTests.size(); i++) {
            String s = dojoTests.get(i).toString();
            JSONObject dojoTest = new JSONObject(s);
            if (dojoTest.get("engagement").toString().equals(engagementID) &&
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
    public void reimportDependencyTrackFindings(final String token, final String engagementId, final InputStream findingsJson, final String testId, final Boolean doNotReactivate) {
        LOGGER.debug("Re-reimport Dependency-Track findings to DefectDojo per Engagement");
        HttpPost request = new HttpPost(baseURL + "/api/v2/reimport-scan/");
        request.addHeader("accept", "application/json");
        request.addHeader("Authorization", "Token " + token);
        InputStreamBody inputStreamBody = new InputStreamBody(findingsJson, ContentType.APPLICATION_OCTET_STREAM, "findings.json");
        HttpEntity fileData = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addPart("file", inputStreamBody)
                .addPart("engagement", new StringBody(engagementId, ContentType.MULTIPART_FORM_DATA))
                .addPart("scan_type", new StringBody("Dependency Track Finding Packaging Format (FPF) Export", ContentType.MULTIPART_FORM_DATA))
                .addPart("verified", new StringBody("true", ContentType.MULTIPART_FORM_DATA))
                .addPart("active", new StringBody("true", ContentType.MULTIPART_FORM_DATA))
                .addPart("minimum_severity", new StringBody("Info", ContentType.MULTIPART_FORM_DATA))
                .addPart("close_old_findings", new StringBody("true", ContentType.MULTIPART_FORM_DATA))
                .addPart("push_to_jira", new StringBody("push_to_jira", ContentType.MULTIPART_FORM_DATA))
                .addPart("do_not_reactivate", new StringBody(doNotReactivate.toString(), ContentType.MULTIPART_FORM_DATA))
                .addPart("test", new StringBody(testId, ContentType.MULTIPART_FORM_DATA))
                .addPart("scan_date", new StringBody(DATE_FORMAT.format(new Date()), ContentType.MULTIPART_FORM_DATA))
                .build();
        request.setEntity(fileData);
        try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
                LOGGER.debug("Successfully reimport findings to DefectDojo");
            } else {
                uploader.handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        }
    }

}
