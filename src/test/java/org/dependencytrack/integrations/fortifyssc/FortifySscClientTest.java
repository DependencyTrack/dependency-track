/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.integrations.fortifyssc;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.commons.io.input.NullInputStream;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import java.net.URL;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

public class FortifySscClientTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options().port(80).httpsPort(443));

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testOneTimeTokenPositiveCase() throws Exception {
        FortifySscUploader uploader = new FortifySscUploader();
        wireMockRule.stubFor(
                post(urlEqualTo("/ssc/api/v1/fileTokens"))
                        .withRequestBody(equalToJson("{ \"fileTokenType\": \"UPLOAD\" }"))
                        .withBasicAuth("admin", "admin")
                        .willReturn(aResponse()
                                .withHeader("Content-Type", "text/json")
                                .withStatus(201)
                                .withBody("{ \"data\": { \"token\": \"db975c97-98b1-4988-8d6a-9c3e044dfff3\" }}"))
        );
        FortifySscClient client = new FortifySscClient(uploader, new URL("http://127.0.0.1/ssc"));
        String token = client.generateOneTimeUploadToken("admin", "admin");
        Assert.assertEquals("db975c97-98b1-4988-8d6a-9c3e044dfff3", token);
    }

    @Test
    public void testOneTimeTokenInvalidCredentials() throws Exception {
        FortifySscUploader uploader = new FortifySscUploader();
        wireMockRule.stubFor(
                post(urlEqualTo("/ssc/api/v1/fileTokens"))
                        .withRequestBody(equalToJson("{ \"fileTokenType\": \"UPLOAD\" }"))
                        .withBasicAuth("admin", "wrong")
                        .willReturn(aResponse()
                                .withStatus(401))
        );
        FortifySscClient client = new FortifySscClient(uploader, new URL("http://127.0.0.1/ssc"));
        String token = client.generateOneTimeUploadToken("admin", "wrong");
        Assert.assertNull(token);
    }

    @Test
    public void testUploadFindingsPositiveCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String applicationVersion = "12345";

        FortifySscUploader uploader = new FortifySscUploader();
        wireMockRule.stubFor(
                post(urlEqualTo("/ssc/upload/resultFileUpload.html?mat=" + token + "&engineType=DEPENDENCY_TRACK&entityId=" + applicationVersion))
                        .withHeader("accept", equalTo("application/xml"))
                        .withQueryParam("engineType", equalTo("DEPENDENCY_TRACK"))
                        .withQueryParam("mat", equalTo(token))
                        .withQueryParam("entityId", equalTo(applicationVersion))
                        .willReturn(aResponse()
                                .withHeader("Content-Type", "application/xml")
                                .withStatus(200))
        );
        FortifySscClient client = new FortifySscClient(uploader, new URL("http://127.0.0.1/ssc"));
        client.uploadDependencyTrackFindings(token, applicationVersion, new NullInputStream(0));
    }

    @Test
    public void testUploadFindingsNegativeCase() throws Exception {
        String token = "db975c97-98b1-4988-8d6a-9c3e044dfff3";
        String applicationVersion = "";

        FortifySscUploader uploader = new FortifySscUploader();
        wireMockRule.stubFor(
                post(urlEqualTo("/ssc/upload/resultFileUpload.html?mat=" + token + "&engineType=DEPENDENCY_TRACK&entityId=" + applicationVersion))
                        .withHeader("accept", equalTo("application/xml"))
                        .withQueryParam("engineType", equalTo("DEPENDENCY_TRACK"))
                        .withQueryParam("mat", equalTo(token))
                        .withQueryParam("entityId", equalTo(applicationVersion))
                        .willReturn(aResponse()
                                .withStatus(400))
        );
        FortifySscClient client = new FortifySscClient(uploader, new URL("http://127.0.0.1/ssc"));
        client.uploadDependencyTrackFindings(token, applicationVersion, new NullInputStream(16));
    }
}