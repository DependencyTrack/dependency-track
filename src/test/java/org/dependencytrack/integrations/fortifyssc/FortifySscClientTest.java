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

import org.apache.commons.io.input.NullInputStream;
import org.apache.http.HttpHeaders;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.rules.ExpectedException;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class FortifySscClientTest {

    private static ClientAndServer mockServer;

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void before() {
        environmentVariables.set("http_proxy", "http://127.0.0.1:1080");
    }

    @BeforeClass
    public static void beforeClass() {
        mockServer = startClientAndServer(1080);
    }

    @AfterClass
    public static void after() {
        mockServer.stop();
    }

    @Test
    public void testOneTimeTokenPositiveCase() throws Exception {
        new MockServerClient("localhost", 1080)
                .when(
                        request()
                                .withMethod("POST")
                                .withHeader(HttpHeaders.AUTHORIZATION, "FortifyToken " + Base64.getEncoder().encodeToString("2d5e4a06-945e-405f-a3c2-112bb3053453".getBytes(StandardCharsets.UTF_8)))
                                .withPath("/ssc/api/v1/fileTokens")
                                .withBody("{\"fileTokenType\":\"UPLOAD\"}")
                )
                .respond(
                        response()
                                .withStatusCode(201)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody("{ \"data\": { \"token\": \"db975c97-98b1-4988-8d6a-9c3e044dfff3\" }}")
                );
        FortifySscUploader uploader = new FortifySscUploader();
        FortifySscClient client = new FortifySscClient(uploader, new URL("https://localhost/ssc"));
        String token = client.generateOneTimeUploadToken("2d5e4a06-945e-405f-a3c2-112bb3053453");
        Assert.assertEquals("db975c97-98b1-4988-8d6a-9c3e044dfff3", token);
    }

    @Test
    public void testOneTimeTokenInvalidCredentials() throws Exception {
        new MockServerClient("localhost", 1080)
                .when(
                        request()
                                .withMethod("POST")
                                .withHeader(HttpHeaders.AUTHORIZATION, "FortifyToken " + Base64.getEncoder().encodeToString("wrong".getBytes(StandardCharsets.UTF_8)))
                                .withPath("/ssc/api/v1/fileTokens")
                                .withBody("{\"fileTokenType\":\"UPLOAD\"}")
                )
                .respond(
                        response()
                                .withStatusCode(401)
                );
        FortifySscUploader uploader = new FortifySscUploader();
        FortifySscClient client = new FortifySscClient(uploader, new URL("https://localhost/ssc"));
        String token = client.generateOneTimeUploadToken("wrong");
        Assert.assertNull(token);
    }

    @Test
    public void testUploadFindingsPositiveCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String applicationVersion = "12345";
        new MockServerClient("localhost", 1080)
                .when(
                        request()
                                .withMethod("POST")
                                .withHeader(HttpHeaders.ACCEPT, "application/xml")
                                .withPath("/ssc/upload/resultFileUpload.html?mat=" + token + "&engineType=DEPENDENCY_TRACK&entityId=" + applicationVersion)
                                .withQueryStringParameter("engineType", "DEPENDENCY_TRACK")
                                .withQueryStringParameter("mat", token)
                                .withQueryStringParameter("entityId", applicationVersion)
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/xml")
                );
        FortifySscUploader uploader = new FortifySscUploader();
        FortifySscClient client = new FortifySscClient(uploader, new URL("https://localhost/ssc"));
        client.uploadDependencyTrackFindings(token, applicationVersion, new NullInputStream(0));
    }

    @Test
    public void testUploadFindingsNegativeCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String applicationVersion = "";
        new MockServerClient("localhost", 1080)
                .when(
                        request()
                                .withMethod("POST")
                                .withHeader(HttpHeaders.ACCEPT, "application/xml")
                                .withPath("/ssc/upload/resultFileUpload.html?mat=" + token + "&engineType=DEPENDENCY_TRACK&entityId=" + applicationVersion)
                                .withQueryStringParameter("engineType", "DEPENDENCY_TRACK")
                                .withQueryStringParameter("mat", token)
                                .withQueryStringParameter("entityId", applicationVersion)
                )
                .respond(
                        response()
                                .withStatusCode(400)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/xml")
                );
        FortifySscUploader uploader = new FortifySscUploader();
        FortifySscClient client = new FortifySscClient(uploader, new URL("https://localhost/ssc"));
        client.uploadDependencyTrackFindings(token, applicationVersion, new NullInputStream(16));
    }
}
