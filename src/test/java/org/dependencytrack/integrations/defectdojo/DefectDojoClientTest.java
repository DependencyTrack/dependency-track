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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.github.tomakehurst.wiremock.matching.EqualToPattern;
import org.apache.commons.io.input.NullInputStream;
import org.apache.http.HttpHeaders;
import org.apache.http.entity.ContentType;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;

public class DefectDojoClientTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule();


    @Test
    public void testUploadFindingsPositiveCase() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/defectdojo/api/v2/import-scan/"))
                .withMultipartRequestBody(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo("12345"))));
        InputStream stream = new ByteArrayInputStream("test input" .getBytes());
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String engagementId = "12345";
        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, new URL(wireMockRule.baseUrl() + "/defectdojo"));
        client.uploadDependencyTrackFindings(token, engagementId, stream);

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/defectdojo/api/v2/import-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo("12345")
                        )).withAnyRequestBodyPart(WireMock.aMultipart().withName("file")
                        .withBody(WireMock.equalTo("test input")).withHeader("Content-Type", WireMock.equalTo(ContentType.APPLICATION_OCTET_STREAM.getMimeType()))));
    }


    @Test
    public void testUploadFindingsNegativeCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff2";
        String engagementId = "";
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/defectdojo/api/v2/import-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token " + token))
                .withMultipartRequestBody(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo(""))).willReturn(WireMock.aResponse().withStatus(400).withHeader(HttpHeaders.CONTENT_TYPE, "application/json")));
        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, new URL(wireMockRule.baseUrl() + "/defectdojo"));
        client.uploadDependencyTrackFindings(token, engagementId, new NullInputStream(16));
        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/defectdojo/api/v2/import-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo("")
                        )));
    }

    @Test
    public void testReimportFindingsPositiveCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String testId = "15";
        String engagementId = "67890";
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/defectdojo/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token " + token))
                .withMultipartRequestBody(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo(engagementId))).willReturn(WireMock.aResponse().withStatus(201).withHeader(HttpHeaders.CONTENT_TYPE, "application/json")));
        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, new URL(wireMockRule.baseUrl() + "/defectdojo"));
        client.reimportDependencyTrackFindings(token, engagementId, new NullInputStream(0), testId, false);
        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/defectdojo/api/v2/reimport-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo(engagementId)
                        )));
    }

    @Test
    public void testReimportFindingsNegativeCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff2";
        String testId = "14";
        String engagementId = "";
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/defectdojo/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token " + token))
                .withMultipartRequestBody(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo(""))).willReturn(WireMock.aResponse().withStatus(400).withHeader(HttpHeaders.CONTENT_TYPE, "application/json")));
        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, new URL(wireMockRule.baseUrl() + "/defectdojo"));
        client.reimportDependencyTrackFindings(token, engagementId, new NullInputStream(16), testId, false);
        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/defectdojo/api/v2/reimport-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart().withName("engagement").
                        withBody(WireMock.equalTo(engagementId)
                        )));
    }
}
