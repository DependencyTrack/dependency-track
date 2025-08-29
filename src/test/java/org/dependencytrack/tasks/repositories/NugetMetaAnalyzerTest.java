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
package org.dependencytrack.tasks.repositories;

import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import java.util.stream.Stream;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.dependencytrack.tasks.repositories.NugetMetaAnalyzer.SUPPORTED_DATE_FORMATS;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

class NugetMetaAnalyzerTest {

    private static ClientAndServer mockServer;

    @BeforeAll
    public static void beforeClass() {
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @AfterAll
    public static void afterClass() {
        mockServer.stop();
    }

    // This test is to check if the analyzer is:
    // * excluding pre-release versions if a release version exists,
    // * including pre-release versions if no release version exists
    // The test is transient depending on the current version of the package
    // retrieved from the repository at the time of running.
    // For example, when it was created, the latest released version of:
    // * Microsoft.Extensions.DependencyInjection was 9.0.0-preview.1.24080.9
    // * OpenTelemetry.Instrumentation.SqlClient was 1.12.0-beta.2 (no release version exists)
    @ParameterizedTest
    @MethodSource("testAnalyzerData")
    void testAnalyzer(String purl, boolean isLatestVersionPreRelease) throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL(purl));
        NugetMetaAnalyzer analyzer = new NugetMetaAnalyzer();

        analyzer.setRepositoryBaseUrl("https://api.nuget.org");
        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertTrue(analyzer.isApplicable(component));
        Assertions.assertEquals(RepositoryType.NUGET, analyzer.supportedRepositoryType());
        Assertions.assertNotNull(metaModel.getLatestVersion());
        Assertions.assertNotNull(metaModel.getPublishedTimestamp());
        Assertions.assertEquals(isLatestVersionPreRelease, metaModel.getLatestVersion().contains("-"));
    }

    static Stream<Arguments> testAnalyzerData() {
        return Stream.of(
            Arguments.of("pkg:nuget/CycloneDX.Core@5.4.0", false),
            Arguments.of("pkg:nuget/Microsoft.Extensions.DependencyInjection@8.0.0", false),
            Arguments.of("pkg:nuget/Microsoft.Extensions.DependencyInjection@8.0.0-beta.21301.5", false),
            Arguments.of("pkg:nuget/OpenTelemetry.Instrumentation.SqlClient@1.12.0-beta.1", true)
        );
    }

    @Test
    void testAnalyzerWithPrivatePackageRepository() throws Exception {
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
                                .withPath("/v3/registrations2-semver2/nunitprivate/5.0.2.json")
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
        Assertions.assertEquals("5.0.2", metaModel.getLatestVersion());
        Assertions.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    void testPublishedDateTimeFormat() throws ParseException {
        Date dateParsed = null;
        for (DateFormat dateFormat : SUPPORTED_DATE_FORMATS) {
            try {
                dateParsed = dateFormat.parse("1900-01-01T00:00:00+00:00");
            } catch (ParseException e) {}
        }
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        Assertions.assertEquals(dateFormat.parse("1900-01-01T00:00:00+00:00"), dateParsed);
    }

    private String readResourceFileToString(String fileName) throws Exception {
        return Files.readString(Paths.get(getClass().getResource(fileName).toURI()));
    }
}
