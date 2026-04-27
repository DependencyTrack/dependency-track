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
package org.dependencytrack.integrations.defectdojo;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.matching.EqualToPattern;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;

@WireMockTest
class DefectDojoClientTest {
    private WireMockRuntimeInfo wmRuntimeInfo;

    @BeforeEach
    final void setUp(WireMockRuntimeInfo wmRuntimeInfo) {
        this.wmRuntimeInfo = wmRuntimeInfo;
    }

    @Test
    void testUploadWithAutoCreateAndDeduplicationEnabled() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v2/import-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token test-api-key"))
                .willReturn(WireMock.aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withStatus(201)));

        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, URI.create(wmRuntimeInfo.getHttpBaseUrl()).toURL());
        InputStream payload = new ByteArrayInputStream("test findings".getBytes());

        client.uploadDependencyTrackFindings(
                "test-api-key",
                null,
                payload,
                true,
                "Test Title",
                "Test Product Type",
                "Test Product",
                "Test Engagement",
                true,
                true
        );

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v2/import-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("auto_create_context")
                        .withBody(WireMock.equalTo("true")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("deduplication_on_engagement")
                        .withBody(WireMock.equalTo("true")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("product_type_name")
                        .withBody(WireMock.equalTo("Test Product Type")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("product_name")
                        .withBody(WireMock.equalTo("Test Product")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("engagement_name")
                        .withBody(WireMock.equalTo("Test Engagement"))));
    }

    @Test
    void testUploadWithAutoCreateAndDeduplicationDisabled() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v2/import-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token test-api-key"))
                .willReturn(WireMock.aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withStatus(201)));

        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, URI.create(wmRuntimeInfo.getHttpBaseUrl()).toURL());
        InputStream payload = new ByteArrayInputStream("test findings".getBytes());

        client.uploadDependencyTrackFindings(
                "test-api-key",
                null,
                payload,
                true,
                "Test Title",
                "Test Product Type",
                "Test Product",
                "Test Engagement",
                true,
                false
        );

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v2/import-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("auto_create_context")
                        .withBody(WireMock.equalTo("true")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("deduplication_on_engagement")
                        .withBody(WireMock.equalTo("false"))));
    }

    @Test
    void testUploadWithoutAutoCreate() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v2/import-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token test-api-key"))
                .willReturn(WireMock.aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withStatus(201)));

        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, URI.create(wmRuntimeInfo.getHttpBaseUrl()).toURL());
        InputStream payload = new ByteArrayInputStream("test findings".getBytes());

        client.uploadDependencyTrackFindings(
                "test-api-key",
                "12345",
                payload,
                true,
                "Test Title"
        );

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v2/import-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("engagement")
                        .withBody(WireMock.equalTo("12345"))));
    }

    @Test
    void testReimportWithAutoCreateAndDeduplicationEnabled() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token test-api-key"))
                .willReturn(WireMock.aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withStatus(201)));

        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, URI.create(wmRuntimeInfo.getHttpBaseUrl()).toURL());
        InputStream payload = new ByteArrayInputStream("test findings".getBytes());

        client.reimportDependencyTrackFindings(
                "test-api-key",
                null,
                payload,
                null,
                false,
                true,
                "Test Title",
                "Test Product Type",
                "Test Product",
                "Test Engagement",
                true,
                true
        );

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v2/reimport-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("auto_create_context")
                        .withBody(WireMock.equalTo("true")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("deduplication_on_engagement")
                        .withBody(WireMock.equalTo("true")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("product_type_name")
                        .withBody(WireMock.equalTo("Test Product Type")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("product_name")
                        .withBody(WireMock.equalTo("Test Product")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("engagement_name")
                        .withBody(WireMock.equalTo("Test Engagement"))));
    }

    @Test
    void testReimportWithAutoCreateAndDeduplicationDisabled() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token test-api-key"))
                .willReturn(WireMock.aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withStatus(201)));

        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, URI.create(wmRuntimeInfo.getHttpBaseUrl()).toURL());
        InputStream payload = new ByteArrayInputStream("test findings".getBytes());

        client.reimportDependencyTrackFindings(
                "test-api-key",
                null,
                payload,
                null,
                false,
                true,
                "Test Title",
                "Test Product Type",
                "Test Product",
                "Test Engagement",
                true,
                false
        );

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v2/reimport-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("auto_create_context")
                        .withBody(WireMock.equalTo("true")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("deduplication_on_engagement")
                        .withBody(WireMock.equalTo("false"))));
    }

    @Test
    void testReimportWithoutAutoCreate() throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("Token test-api-key"))
                .willReturn(WireMock.aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withStatus(201)));

        DefectDojoUploader uploader = new DefectDojoUploader();
        DefectDojoClient client = new DefectDojoClient(uploader, URI.create(wmRuntimeInfo.getHttpBaseUrl()).toURL());
        InputStream payload = new ByteArrayInputStream("test findings".getBytes());

        client.reimportDependencyTrackFindings(
                "test-api-key",
                "12345",
                payload,
                "67890",
                false,
                true,
                "Test Title"
        );

        WireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/api/v2/reimport-scan/"))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("engagement")
                        .withBody(WireMock.equalTo("12345")))
                .withAnyRequestBodyPart(WireMock.aMultipart()
                        .withName("test")
                        .withBody(WireMock.equalTo("67890"))));
    }
}
