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
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

class NugetMetaAnalyzerTest {

    public static final String LOCALHOST_REPO_INDEX = "http://localhost:1080/artifactory/api/nuget/v3/nuget-repo/index.json";
    private static ClientAndServer mockServer;

    @BeforeAll
    static void beforeClass() throws Exception {
        mockServer = ClientAndServer.startClientAndServer(1080);

        setupMockServerClient(
                "/artifactory/api/nuget/v3/nuget-repo/index.json",
                "/unit/tasks/repositories/https---localhost-nuget-artifactory.v3-index.json",
                null, "application/json", 200
        );
    }

    private static void setupMockServerClient(
            String path,
            String responseFile,
            String authHeader
    ) throws Exception {
        setupMockServerClient(path, responseFile, authHeader, "application/json", 200);
    }

    private static void setupMockServerClient(
            String path,
            String responseFile,
            String authHeader,
            String contentType,
            int statusCode
    ) throws Exception {

        List<Header> headers = new ArrayList<>();
        if (authHeader != null) {
            headers.add(new Header("Authorization", authHeader));
        }

        new MockServerClient("localhost", 1080)
                .when(
                        request()
                                .withMethod("GET")
                                .withPath(path)
                                .withHeaders(headers)
                )
                .respond(
                        response()
                                .withStatusCode(statusCode)
                                .withHeader(HttpHeaders.CONTENT_TYPE, contentType)
                                .withBody(Files.readString(Paths.get(NugetMetaAnalyzerTest.class.getResource(responseFile).toURI())))
                );
    }

    @AfterAll
    static void afterClass() {
        mockServer.stop();
    }

    /**
     * Various tests to confirm error handling behaviour when, e.g. the repo or package cannot
     * be found. The analyzer should still return a MetaModel in these cases with null version and
     * published. The analyzer should NOT crash.
     */
    @Nested
    class ErrorHandlingTests {

        @Test
        void testBaseUrlNotFoundBehaviourWhenSettingRepoUrl() {
            Assertions.assertDoesNotThrow(() -> {
                var analyzer = new NugetMetaAnalyzer();
                analyzer.setRepositoryBaseUrl("http://no-such-api.this-host-does-not-exist-nuget-repo.invalid");
            });
        }

        @Test
        void testBaseUrlNotFoundBehaviourWhenCallingAnalyze() {
            Assertions.assertDoesNotThrow(() -> {
                var analyzer = new NugetMetaAnalyzer();
                analyzer.setRepositoryBaseUrl("http://no-such-api.this-host-does-not-exist-nuget-repo.invalid");

                Component component = new Component();
                component.setPurl(new PackageURL("pkg:nuget/CycloneDX.Core@5.4.0"));
                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertTrue(analyzer.isApplicable(component));
                assertMetaModelExistsButEmpty(analyzer, metaModel);
            });
        }

        @Test
        void testRepoValidButPackageNotFoundBehaviour() throws Exception {

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/testing.no.such.package/index.json",
                    "/unit/tasks/repositories/https---nuget.org.no-such-package.xml",
                    null,
                    "application/xml",
                    404
            );

            Component component = new Component();
            component.setPurl(new PackageURL("pkg:nuget/Testing.No.Such.Package@8.0.0"));

            var analyzer = new NugetMetaAnalyzer();
            analyzer.setRepositoryBaseUrl(LOCALHOST_REPO_INDEX);
            MetaModel metaModel = analyzer.analyze(component);

            assertMetaModelExistsButEmpty(analyzer, metaModel);
        }

        @Test
        void testErrorBetweenPageRequestsReturnsNullData() throws Exception {

            var analyzer = new NugetMetaAnalyzer();
            analyzer.setRepositoryBaseUrl(LOCALHOST_REPO_INDEX);

            var component = new Component();
            component.setName("Microsoft.Data.SqlClient");
            component.setPurl(new PackageURL("pkg:nuget/Microsoft.Data.SqlClient@5.1.0"));

            mockServer.reset();

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/index.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.v3-index.json",
                    null, "application/json", 200
            );

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/index.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.index.json",
                    null
            );

            // Page 2
            new MockServerClient("localhost", 1080)
                    .when(
                            request()
                                    .withMethod("GET")
                                    .withPath("/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/5.1.1/6.1.0.json")
                    )
                    .respond(
                            response()
                                    .withStatusCode(401)
                                    .withHeader(HttpHeaders.CONTENT_TYPE, "application/xml")
                                    .withBody("<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>TestError</Code><Message>Not Authorised</Message></Error>")
                    );

            // Page 1
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/1.0.19123.2-preview/5.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page1.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertNull(metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testNullComponentThrowsIllegalArgumentException() {
            var analyzer = new NugetMetaAnalyzer();
            analyzer.setRepositoryBaseUrl(LOCALHOST_REPO_INDEX);
            Assertions.assertThrows(IllegalArgumentException.class, () -> analyzer.analyze(null));
        }

    }

    private void assertMetaModelExistsButEmpty(NugetMetaAnalyzer analyzer, MetaModel metaModel) {
        Assertions.assertEquals(RepositoryType.NUGET, analyzer.supportedRepositoryType());
        Assertions.assertNull(metaModel.getLatestVersion());
        Assertions.assertNull(metaModel.getPublishedTimestamp());
    }

    /**
     * Tests against JSON files captured from nuget.org to avoid making live calls and to control test data state. Main
     * difference between Nuget and the Artifactory tests is Nuget includes a published date value. To run these tests
     * against the live nuget feed, simply change the URL in the setup method to api.nuget.org - you can ignore the
     * MockServerClient calls because they won't be invoked.
     */
    @Nested
    class NugetTests {

        private Component component;
        private NugetMetaAnalyzer analyzer;

        @BeforeEach
        void setUp() throws Exception {
            this.component = new Component();
            this.component.setInternal(false);
            this.component.setName("Microsoft.Data.SqlClient");
            this.component.setPurl(new PackageURL("pkg:nuget/Microsoft.Data.SqlClient@5.0.1"));

            this.analyzer = new NugetMetaAnalyzer();
            this.analyzer.setRepositoryBaseUrl("https://api.nuget.org");
        }

        @Test
        void testAnalyzerWithMultipleInlinePages() throws Exception {

            // This test also effectively covers pre-release versions (e.g. 6.1.0-preview2.25178.5)
            // and unlisted versions (6.1.0) by returning 6.0.2

            setupMockServerClient(
                    "/v3/index.json",
                    "/unit/tasks/repositories/https---nuget.org.v3-index.json",
                    null
            );

            setupMockServerClient(
                    "/v3/registration5-gz-semver2/microsoft.data.sqlclient/index.json",
                    "/unit/tasks/repositories/https---nuget.org.registration-semver2.mds.index-inline-pages.json",
                    null
            );

            this.analyzer.setRepositoryBaseUrl("http://localhost:1080/v3/index.json");

            MetaModel metaModel = analyzer.analyze(component);

            Assertions.assertTrue(analyzer.isApplicable(component));
            Assertions.assertEquals(RepositoryType.NUGET, analyzer.supportedRepositoryType());
            Assertions.assertNotNull(metaModel.getLatestVersion());

            Assertions.assertEquals("6.0.2", metaModel.getLatestVersion());

            // nuget feeds should return a published date
            Assertions.assertNotNull(metaModel.getPublishedTimestamp());
            Date expected = analyzer.parseUpdateTime("2025-04-25T21:29:47.897+00:00");
            Assertions.assertEquals(expected, metaModel.getPublishedTimestamp());
        }

    }

    /**
     * Artifactory doesn't provide published dates and favours (only uses?) paged registration data.
     * This collection uses the service index to find the best RegistrationsBaseUrl, in this case
     * for semver2
     */
    @Nested
    class ArtifactoryTestsSemver2Tests {

        NugetMetaAnalyzer analyzer;
        Component component;

        @BeforeEach
        void setUp() throws Exception {

            this.analyzer = new NugetMetaAnalyzer();
            this.analyzer.setRepositoryBaseUrl(LOCALHOST_REPO_INDEX);

            this.component = new Component();
            this.component.setName("Microsoft.Data.SqlClient");
            this.component.setPurl(new PackageURL("pkg:nuget/Microsoft.Data.SqlClient@5.1.0"));

            mockServer.reset();

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/index.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.v3-index.json",
                    null, "application/json", 200
            );

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/index.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.index.json",
                    null
            );

        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfo() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/5.1.1/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page2.json",
                    null
            );

            // Page 1
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/1.0.19123.2-preview/5.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page1.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("6.0.2", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfoIgnorePreReleaseAndUnlisted() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/5.1.1/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page2-check-pre-release.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("5.1.2", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfoWhenPage2AllUnlisted() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/5.1.1/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page2-all-unlisted.json",
                    null
            );

            // Page 1
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/1.0.19123.2-preview/5.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page1.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("5.1.0", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfoWhenPage2AllPreRelease() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/5.1.1/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page2-all-pre-release.json",
                    null
            );

            // Page 1
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient/page/1.0.19123.2-preview/5.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver2.mds.page1.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("5.1.0", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithPreReleaseOnlyVersionsReturnsLatestPreReleaseVersion() throws Exception {

            // Test for log warning covered in 5075 - ensure no errors are thrown / logged
            // when no release versions exist

            setupMockServerClient(
                    "/v3/index.json",
                    "/unit/tasks/repositories/https---nuget.org.v3-index.json",
                    null
            );

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/opentelemetry.instrumentation.sqlclient/index.json",
                    "/unit/tasks/repositories/https---nuget.org.registration-semver2.beta-releases-only.index-inline-pages.json",
                    null
            );

            var betaOnlyComponent = new Component();
            betaOnlyComponent.setInternal(false);
            betaOnlyComponent.setName("OpenTelemetry.Instrumentation.SqlClient");
            betaOnlyComponent.setPurl(new PackageURL("pkg:nuget/OpenTelemetry.Instrumentation.SqlClient@1.12.0-beta.2"));

            MetaModel metaModel = analyzer.analyze(betaOnlyComponent);

            Assertions.assertTrue(analyzer.isApplicable(betaOnlyComponent));
            Assertions.assertEquals(RepositoryType.NUGET, analyzer.supportedRepositoryType());
            Assertions.assertNotNull(metaModel.getLatestVersion());
            Assertions.assertEquals("1.12.0-beta.2", metaModel.getLatestVersion());
            Date expected = analyzer.parseUpdateTime("2025-07-15T04:42:33.33+00:00");
            Assertions.assertEquals(expected, metaModel.getPublishedTimestamp());
        }

    }

    /**
     * Artifactory doesn't provide published dates and favours (only uses?) paged registration data.
     * This collection forces a semver1 RegistrationsBaseUrl. The chosen test package,
     * microsoft.data.sqlclient, returns the same number of items (64) as the semver2 version but the
     * results appear on a single page instead of 2 with the semver2 version.
     */
    @Nested
    class ArtifactoryTestsSemver1Tests {

        NugetMetaAnalyzer analyzer;
        Component component;

        @BeforeEach
        void setUp() throws Exception {

            this.analyzer = new NugetMetaAnalyzer();
            this.analyzer.setRepositoryBaseUrl(LOCALHOST_REPO_INDEX);
            this.analyzer.setRegistrationsBaseUrl("http://localhost:1080/artifactory/api/nuget/v3/nuget-repo/registration/");

            this.component = new Component();
            this.component.setName("Microsoft.Data.SqlClient");
            this.component.setPurl(new PackageURL("pkg:nuget/Microsoft.Data.SqlClient@5.1.0"));

            mockServer.reset();

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/index.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.v3-index.json",
                    null, "application/json", 200
            );

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration/microsoft.data.sqlclient/index.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver1.mds.index.json",
                    null
            );

            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration/microsoft.data.sqlclient/page/1.0.19123.2-preview/1.1.2.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver1.mds.page1.json",
                    null
            );
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfo() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration/microsoft.data.sqlclient/page/5.2.2/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver1.mds.page2.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("6.0.2", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfoIgnorePreReleaseAndUnlisted() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration/microsoft.data.sqlclient/page/5.2.2/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver1.mds.page2-check-pre-release.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("6.0.1", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfoWhenPage2AllUnlisted() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration/microsoft.data.sqlclient/page/5.2.2/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver1.mds.page2-all-unlisted.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("1.1.2", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerWithMultipageRegistrationInfoWhenPage2AllPreRelease() throws Exception {

            // Page 2
            setupMockServerClient(
                    "/artifactory/api/nuget/v3/nuget-repo/registration/microsoft.data.sqlclient/page/5.2.2/6.1.0.json",
                    "/unit/tasks/repositories/https---localhost-nuget-artifactory.registration-semver1.mds.page2-all-pre-release.json",
                    null
            );

            MetaModel metaModel = analyzer.analyze(component);
            Assertions.assertEquals("1.1.2", metaModel.getLatestVersion());
            Assertions.assertNull(metaModel.getPublishedTimestamp());
        }

    }

    @Nested
    class DateParserTests {

        NugetMetaAnalyzer analyzer = new NugetMetaAnalyzer();

        @ParameterizedTest
        @ValueSource(strings = {
                "1900-01-01T00:00:00+00:00",
                "2025-08-13T23:22:21.20+01:00",
                "2025-08-13T23:22:21Z",
                "2020-08-04T10:39:03.7136823",
                "2025-08-13T23:22:21",
                "2020-08-04T10:39:03.7136823",
                "2023-03-28T22:26:40.43+00:00",
                "2025-08-14T08:12:23.8207879Z"
        })
        void shouldParseValidDateFormats(String dateString) {
            Date result = this.analyzer.parseUpdateTime(dateString);
            Assertions.assertNotNull(result);
        }

        @Test
        void shouldReturnNullForBlankString() {
            Assertions.assertNull(this.analyzer.parseUpdateTime("   "));
        }

        @Test
        void shouldReturnNullForInvalidDate() {
            Assertions.assertNull(this.analyzer.parseUpdateTime("not-a-date"));
        }

        @Test
        void shouldReturnNullForNullInput() {
            Assertions.assertNull(this.analyzer.parseUpdateTime(null));
        }

    }

}
