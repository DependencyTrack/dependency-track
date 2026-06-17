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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.matching.EqualToPattern;
import org.apache.http.HttpHeaders;
import org.apache.http.entity.ContentType;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.secret.TestSecretManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;


class FortifySscClientTest extends PersistenceCapableTest {

    @RegisterExtension
    private static final WireMockExtension wireMock = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    private static HttpClient httpClient;

    @BeforeAll
    static void beforeAll() {
        httpClient = HttpClient.newHttpClient();
    }

    @AfterAll
    static void afterAll() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @Test
    void testOneTimeTokenPositiveCase() throws Exception {
        wireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/ssc/api/v1/fileTokens"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("FortifyToken " + Base64.getEncoder().encodeToString("2d5e4a06-945e-405f-a3c2-112bb3053453".getBytes(StandardCharsets.UTF_8))))
                .withRequestBody(WireMock.equalToJson("{\"fileTokenType\":\"UPLOAD\"}"))
                .willReturn(WireMock.aResponse().withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withBody("{ \"data\": { \"token\": \"db975c97-98b1-4988-8d6a-9c3e044dfff3\" }}").withStatus(201)));
        FortifySscUploader uploader = new FortifySscUploader(httpClient, new TestSecretManager());
        uploader.setQueryManager(qm);
        FortifySscClient client = new FortifySscClient(httpClient, uploader, URI.create(wireMock.baseUrl() + "/ssc").toURL());
        String token = client.generateOneTimeUploadToken("2d5e4a06-945e-405f-a3c2-112bb3053453");
        Assertions.assertEquals("db975c97-98b1-4988-8d6a-9c3e044dfff3", token);
    }

    @Test
    void testOneTimeTokenInvalidCredentials() throws Exception {
        wireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/ssc/api/v1/fileTokens"))
                .withHeader(HttpHeaders.AUTHORIZATION, new EqualToPattern("FortifyToken " + Base64.getEncoder().encodeToString("wrong".getBytes(StandardCharsets.UTF_8))))
                .withRequestBody(WireMock.equalToJson("{\"fileTokenType\":\"UPLOAD\"}"))
                .willReturn(WireMock.aResponse().withHeader(HttpHeaders.CONTENT_TYPE, "application/json").withStatus(401)));
        FortifySscUploader uploader = new FortifySscUploader(httpClient, new TestSecretManager());
        uploader.setQueryManager(qm);
        FortifySscClient client = new FortifySscClient(httpClient, uploader, URI.create(wireMock.baseUrl() + "/ssc").toURL());
        String token = client.generateOneTimeUploadToken("wrong");
        Assertions.assertNull(token);
    }

    @Test
    void testUploadFindingsPositiveCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String applicationVersion = "12345";
        wireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/ssc/upload/resultFileUpload.html"))
                .withHeader(HttpHeaders.ACCEPT, new EqualToPattern("application/xml"))
                .withQueryParam("engineType", new EqualToPattern("DEPENDENCY_TRACK"))
                .withQueryParam("mat", new EqualToPattern(token))
                .withQueryParam("entityId", new EqualToPattern(applicationVersion))
                .willReturn(WireMock.aResponse().withHeader(HttpHeaders.CONTENT_TYPE, "application/xml").withStatus(200)));
        FortifySscUploader uploader = new FortifySscUploader(httpClient, new TestSecretManager());
        uploader.setQueryManager(qm);
        FortifySscClient client = new FortifySscClient(httpClient, uploader, URI.create(wireMock.baseUrl() + "/ssc").toURL());
        InputStream stream = new ByteArrayInputStream("test input".getBytes());
        client.uploadDependencyTrackFindings(token, applicationVersion, stream);

        wireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/ssc/upload/resultFileUpload.html"))
                .withQueryParam("engineType", new EqualToPattern("DEPENDENCY_TRACK"))
                .withQueryParam("mat", new EqualToPattern(token))
                .withQueryParam("entityId", new EqualToPattern(applicationVersion))
                .withAnyRequestBodyPart(WireMock.aMultipart().withName("files[]")
                        .withBody(WireMock.equalTo("test input")).withHeader("Content-Type", WireMock.equalTo(ContentType.APPLICATION_OCTET_STREAM.getMimeType()))));
    }

    @Test
    void testUploadFindingsNegativeCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String applicationVersion = "";
        wireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/ssc/upload/resultFileUpload.html"))
                .withHeader(HttpHeaders.ACCEPT, new EqualToPattern("application/xml"))
                .withQueryParam("engineType", new EqualToPattern("DEPENDENCY_TRACK"))
                .withQueryParam("mat", new EqualToPattern(token))
                .withQueryParam("entityId", new EqualToPattern(applicationVersion))
                .willReturn(WireMock.aResponse().withHeader(HttpHeaders.CONTENT_TYPE, "application/xml").withStatus(400)));
        FortifySscUploader uploader = new FortifySscUploader(httpClient, new TestSecretManager());
        uploader.setQueryManager(qm);
        FortifySscClient client = new FortifySscClient(httpClient, uploader, URI.create(wireMock.baseUrl() + "/ssc").toURL());
        InputStream stream = new ByteArrayInputStream("test input".getBytes());
        client.uploadDependencyTrackFindings(token, applicationVersion, stream);

        wireMock.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/ssc/upload/resultFileUpload.html"))
                .withQueryParam("engineType", new EqualToPattern("DEPENDENCY_TRACK"))
                .withQueryParam("mat", new EqualToPattern(token))
                .withQueryParam("entityId", new EqualToPattern(applicationVersion))
                .withAnyRequestBodyPart(WireMock.aMultipart().withName("files[]")
                        .withBody(WireMock.equalTo("test input")).withHeader("Content-Type", WireMock.equalTo(ContentType.APPLICATION_OCTET_STREAM.getMimeType()))));

    }
}
