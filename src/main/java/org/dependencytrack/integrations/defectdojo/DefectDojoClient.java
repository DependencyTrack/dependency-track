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
import org.apache.http.HttpStatus;
import org.json.JSONArray;
import org.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
        request.addHeader("accept", "application/json");
        request.addHeader("Authorization", "Token " + token);
        List<NameValuePair> nameValuePairs = new ArrayList<>();
        nameValuePairs.add(new BasicNameValuePair("engagement", engagementId));
        nameValuePairs.add(new BasicNameValuePair("scan_type", "Dependency Track Finding Packaging Format (FPF) Export"));
        nameValuePairs.add(new BasicNameValuePair("verified", "true"));
        nameValuePairs.add(new BasicNameValuePair("active", "true"));
        nameValuePairs.add(new BasicNameValuePair("minimum_severity", "Info"));
        nameValuePairs.add(new BasicNameValuePair("close_old_findings", "true"));
        nameValuePairs.add(new BasicNameValuePair("push_to_jira", "false"));
        nameValuePairs.add(new BasicNameValuePair("scan_date", DATE_FORMAT.format(new Date())));

        HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addBinaryBody("file", findingsJson, ContentType.APPLICATION_JSON, "findings.json")
                .build();
        request.setEntity(data);
        request.setEntity(new UrlEncodedFormEntity(nameValuePairs, StandardCharsets.UTF_8));
        try {
            CloseableHttpResponse response = HttpClientPool.getClient().execute(request);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
                LOGGER.debug("Successfully uploaded findings to DefectDojo");
            } else {
                LOGGER.warn("DefectDojo Client did not receive expected response while attempting to upload "
                        + "Dependency-Track findings. HTTP response code: "
                        + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
                uploader.handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException ex) {
            LOGGER.error("Error while sending request from upload DT findings defectDojo Client" + ex.getMessage());
            LOGGER.error("Error while sending request from upload DT findings defectDojo Client" + ex.getStackTrace());
        }
    }

    // Pulling DefectDojo 'tests' API endpoint with engagementID filter on, and retrieve a list of existing tests
    public ArrayList getDojoTestIds(final String token, final String eid) {
        LOGGER.debug("Pulling DefectDojo Tests API ...");
        String tests_uri = "/api/v2/tests/";
        LOGGER.debug("Make the first pagination call");
        HttpGet request = new HttpGet(baseURL + tests_uri + "?limit=100&engagement=" + eid);
        request.addHeader("accept", "application/json");
        request.addHeader("Authorization", "Token " + token);
        try{
        CloseableHttpResponse response = HttpClientPool.getClient().execute(request);
        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            if (response.getEntity()!=null) {
                String stringResponse = EntityUtils.toString(response.getEntity());
                JSONObject dojoObj = new JSONObject(stringResponse);
                JSONArray dojoArray = dojoObj.getJSONArray("results");
                ArrayList dojoTests = jsonToList(dojoArray);
                String nextUrl = "";
                while (dojoObj.get("next") != null) {
                    nextUrl = dojoObj.get("next").toString();
                    LOGGER.debug("Making the subsequent pagination call on " + nextUrl);
                    request = new HttpGet(nextUrl);
                    request.addHeader("accept", "application/json");
                    request.addHeader("Authorization", "Token " + token);
                    response = HttpClientPool.getClient().execute(request);
                    nextUrl = dojoObj.get("next").toString();
                    stringResponse = EntityUtils.toString(response.getEntity());
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
        }}catch (IOException ex){
            LOGGER.error("Error while getting dojo test id's"+ex.getMessage());
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
    public void reimportDependencyTrackFindings(final String token, final String engagementId, final InputStream findingsJson, final String testId) {
        LOGGER.debug("Re-reimport Dependency-Track findings to DefectDojo per Engagement");
        HttpPost request = new HttpPost(baseURL + "/api/v2/reimport-scan/");
        request.addHeader("accept", "application/json");
        request.addHeader("Authorization", "Token " + token);
        List<NameValuePair> nameValuePairs = new ArrayList<>();
        nameValuePairs.add(new BasicNameValuePair("engagement", engagementId));
        nameValuePairs.add(new BasicNameValuePair("scan_type", "Dependency Track Finding Packaging Format (FPF) Export"));
        nameValuePairs.add(new BasicNameValuePair("verified", "true"));
        nameValuePairs.add(new BasicNameValuePair("active", "true"));
        nameValuePairs.add(new BasicNameValuePair("minimum_severity", "Info"));
        nameValuePairs.add(new BasicNameValuePair("close_old_findings", "true"));
        nameValuePairs.add(new BasicNameValuePair("push_to_jira", "false"));
        nameValuePairs.add(new BasicNameValuePair("test", testId));
        nameValuePairs.add(new BasicNameValuePair("scan_date", DATE_FORMAT.format(new Date())));
        request.setEntity(new UrlEncodedFormEntity(nameValuePairs, StandardCharsets.UTF_8));
        HttpEntity fileData = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addBinaryBody("file", findingsJson, ContentType.APPLICATION_JSON, "findings.json")
                .build();
        request.setEntity(fileData);
        try{
            CloseableHttpResponse response = HttpClientPool.getClient().execute(request);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
                LOGGER.debug("Successfully reimport findings to DefectDojo");
            } else {
                LOGGER.warn("DefectDojo Client did not receive expected response while attempting to reimport"
                        + "Dependency-Track findings. HTTP response code: "
                        + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
                uploader.handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
            }
        }catch (IOException ex){
            LOGGER.error("Error while sending request from reimport DT findings defectDojo Client" + ex.getMessage());
            LOGGER.error("Error while sending request from reimport DT findings defectDojo Client" + ex.getStackTrace());
        }
    }

}
