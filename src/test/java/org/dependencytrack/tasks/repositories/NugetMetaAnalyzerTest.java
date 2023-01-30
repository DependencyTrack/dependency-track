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
package org.dependencytrack.tasks.repositories;

import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class NugetMetaAnalyzerTest {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @AfterClass
    public static void afterClass() {
        mockServer.stop();
    }

    @Test
    public void testAnalyzer() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:nuget/NUnit@3.8.0"));
        NugetMetaAnalyzer analyzer = new NugetMetaAnalyzer();

        analyzer.setRepositoryBaseUrl("https://api.nuget.org");
        MetaModel metaModel = analyzer.analyze(component);

        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.NUGET, analyzer.supportedRepositoryType());
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerWithPrivatePackageRepository() throws Exception {
        String mockIndexResponse = readResourceFileToString("/unit/tasks/repositories/https---localhost-1080-v3-index.json");
        new MockServerClient("localhost", mockServer.getPort())
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/v3/index.json")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody(mockIndexResponse)
                );
        String encodedBasicHeader = "Basic OnBhc3N3b3Jk";

        String mockVersionResponse = readResourceFileToString("/unit/tasks/repositories/https---localhost-1080-v3-flat2" +
               "-nunitprivate-index.json");
        new MockServerClient("localhost", mockServer.getPort())
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/v3/flat2/nunitprivate/index.json")
                                .withHeader("Authorization", encodedBasicHeader)
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody(mockVersionResponse)
                );

        String mockRegistrationResponse = readResourceFileToString("/unit/tasks/repositories/https---localhost-1080-v3" +
                "-registrations2-nunitprivate-502.json");
        new MockServerClient("localhost", mockServer.getPort())
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/v3/registrations2/nunitprivate/5.0.2.json")
                                .withHeader("Authorization", encodedBasicHeader)
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody(mockRegistrationResponse)
                );
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:nuget/NUnitPrivate@5.0.1"));
        NugetMetaAnalyzer analyzer = new NugetMetaAnalyzer();
        analyzer.setRepositoryUsernameAndPassword(null, "password");
        analyzer.setRepositoryBaseUrl("http://localhost:1080");
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertEquals("5.0.2", metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }
    private String readResourceFileToString(String fileName) throws Exception {
        return Files.readString(Paths.get(getClass().getResource(fileName).toURI()));
    }
}
