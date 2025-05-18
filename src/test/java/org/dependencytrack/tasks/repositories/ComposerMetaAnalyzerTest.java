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

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.io.File;
import java.io.FileInputStream;
import java.text.SimpleDateFormat;

import org.apache.http.HttpHeaders;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import com.github.packageurl.PackageURL;

class ComposerMetaAnalyzerTest {

        private static ClientAndServer mockServer;

        @BeforeAll
        public static void beforeClass() {
                mockServer = ClientAndServer.startClientAndServer(1080);
        }

        @AfterAll
        public static void afterClass() {
                mockServer.stop();
        }

        @BeforeEach
        public void setUp() {
                mockServer.reset();
        }

        @Test
        void testAnalyzer() throws Exception {
                Component component = new Component();
                component.setPurl(new PackageURL("pkg:composer/phpunit/phpunit@1.0.0"));

                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();
                Assertions.assertTrue(analyzer.isApplicable(component));
                Assertions.assertEquals(RepositoryType.COMPOSER, analyzer.supportedRepositoryType());
                MetaModel metaModel = analyzer.analyze(component);
                Assertions.assertNotNull(metaModel.getLatestVersion());
                Assertions.assertNotNull(metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerV1() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/monolog/monolog@v1.1.0"));
                final File packagistFile = getPackageResourceFile("repo.packagist.org.v1", "monolog", "monolog");
                final File packagistRepoRootFile = getRepoResourceFile("repo.packagist.org.v1", "packages");

                analyzer.setRepositoryId("1");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/p/monolog/monolog.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("3.8.1", metaModel.getLatestVersion());
                Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-12-05 17:15:07 Z"), metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerFindsVersionWithLeadingVV2() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/typo3/class-alias-loader@v1.1.0"));
                final File packagistFile = getPackageResourceFile("repo.packagist.org", "typo3", "class-alias-loader");
                final File packagistRepoRootFile = getRepoResourceFile("repo.packagist.org", "packages");

                analyzer.setRepositoryId("2");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/p2/typo3/class-alias-loader.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
                Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());
        }

        @Test
        void testAnalyzerInlinePackageAndRepoPath() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/dummyspace/base@v1.1.0"));
                final File packagistRepoRootFile = getRepoResourceFile("composer.dummy.com.therepo", "packages");

                analyzer.setRepositoryId("3");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d/therepo", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/therepo/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/therepo/p2/dummyspace/base.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json"));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("1.18.0", metaModel.getLatestVersion());
                Assertions.assertNull(metaModel.getPublishedTimestamp());

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/therepo/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/therepo/p2/dummyspace/base.json"),
                                org.mockserver.verify.VerificationTimes.exactly(0));

                mockClient.verify(
                                request(),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                component.setPurl(new PackageURL("pkg:composer/something/something@v1.1.0"));
                MetaModel metaModel2 = analyzer.analyze(component);

                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());

                // no extra calls should have been made
                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/therepo/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/therepo/p2/dummyspace/base.json"),
                                org.mockserver.verify.VerificationTimes.exactly(0));

                mockClient.verify(
                                request(),
                                org.mockserver.verify.VerificationTimes.exactly(1));
        }

        @Test
        void testAnalyzerIncludesAndRepoPath() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/space/cowboy@v1.1.0"));
                final File packagistRepoRootFile = getRepoResourceFile("composer.include.com.userpass", "packages");
                final File packagistFile = getPackageResourceFile("composer.include.com.userpass", "space", "cowboy");

                analyzer.setRepositoryId("4");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d/user:pass/", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")

                // .withPath("/user%3Apass/user%3Apass/include/all%2410dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")
                )
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("2.3.8", metaModel.getLatestVersion());
                // Timestamps are in invalid format for this repo
                Assertions.assertNull(metaModel.getPublishedTimestamp());

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request(),
                                org.mockserver.verify.VerificationTimes.exactly(2));

                component.setPurl(new PackageURL("pkg:composer/something/something@v1.1.0"));
                MetaModel metaModel2 = analyzer.analyze(component);

                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());

                // no extra calls should have been made
                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request(),
                                org.mockserver.verify.VerificationTimes.exactly(2));
        }

        @Test
        void testAnalyzerIncludesWithMetadataUrl() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/space/cowboy@v1.1.0"));
                final File packagistRepoRootFile = getRepoResourceFile("composer.include.com.metadata", "packages");
                final File packagistFile = getPackageResourceFile("composer.include.com.metadata", "space", "cowboy");

                analyzer.setRepositoryId("5");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d/user:pass/", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json"));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/p2/space/cowboy.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("6.6.6", metaModel.getLatestVersion());
                Assertions.assertNull(metaModel.getPublishedTimestamp());

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json"),
                                org.mockserver.verify.VerificationTimes.exactly(0));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/p2/space/cowboy.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request(),
                                org.mockserver.verify.VerificationTimes.exactly(2));

                component.setPurl(new PackageURL("pkg:composer/something/something@v1.1.0"));
                MetaModel metaModel2 = analyzer.analyze(component);

                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());

                // no extra calls should have been made, only a metadata call as those are not
                // cached
                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json"),
                                org.mockserver.verify.VerificationTimes.exactly(0));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/user:pass/p2/space/cowboy.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request(),
                                org.mockserver.verify.VerificationTimes.exactly(3));
        }

        @Test
        void testAnalyzerCacheOfRoot() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/typo3/class-alias-loader@v1.1.0"));
                final File packagistFile = getPackageResourceFile("repo.packagist.org", "typo3", "class-alias-loader");
                final File packagistRepoRootFile = getRepoResourceFile("repo.packagist.org", "packages");

                analyzer.setRepositoryId("6");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/p2/typo3/class-alias-loader.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
                Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());
                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/p2/typo3/class-alias-loader.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                analyzer.analyze(component);
                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/p2/typo3/class-alias-loader.json"),
                                org.mockserver.verify.VerificationTimes.exactly(2));

        }

        @Test
        void testAnalyzerEmptyRoot() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/empty/root@v1.1.0"));
                final File packagistRepoRootFile = getRepoResourceFile("repo.empty.org", "packages");

                analyzer.setRepositoryId("7");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                MetaModel metaModel = analyzer.analyze(component);
                Assertions.assertNull(metaModel.getLatestVersion());
                Assertions.assertNull(metaModel.getPublishedTimestamp());

                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

                MetaModel metaModel2 = analyzer.analyze(component);
                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());
                mockClient.verify(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"),
                                org.mockserver.verify.VerificationTimes.exactly(1));

        }

        @Test
        void testAnalyzerDrupalV2NoTimeWithAvailablePackagePatterns() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/drupal/mollie@v2.0.0"));
                final File packagistFile = getPackageResourceFile("packages.drupal.org", "drupal", "mollie");
                final File packagistRepoRootFile = getRepoResourceFile("packages.drupal.org", "packages");

                analyzer.setRepositoryId("8");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/files/packages/8/p2/drupal/mollie.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("2.2.1", metaModel.getLatestVersion());
                Assertions.assertEquals(null, metaModel.getPublishedTimestamp());

                component.setPurl(new PackageURL("pkg:composer/phpunit/phpunit@v2.0.0"));
                MetaModel metaModel2 = analyzer.analyze(component);

                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());

                // no calls should have been made for non-matching package
                mockClient.verify(
                                request()
                                                .withMethod("GET"),
                                org.mockserver.verify.VerificationTimes.exactly(2));
        }

        @Test
        void testAnalyzerAvailablePackages() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/io/captain-hook@v0.0.0"));
                final File packagistFile = getPackageResourceFile("composer.available.com", "io", "captain-hook");
                final File packagistRepoRootFile = getRepoResourceFile("composer.available.com", "packages");

                analyzer.setRepositoryId("9");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/repository/p2/io/captain-hook.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
                Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());

                component.setPurl(new PackageURL("pkg:composer/phpunit/phpunit@v0.0.0"));
                MetaModel metaModel2 = analyzer.analyze(component);

                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());

                // no calls should have been made for non-matching package
                mockClient.verify(
                                request()
                                                .withMethod("GET"),
                                org.mockserver.verify.VerificationTimes.exactly(2));
        }

        @Test
        void testAnalyzerNotInAvailablePackagesAndMatchingLogic() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/io/captain-hook@v0.0.0"));
                final File packagistFile = getPackageResourceFile("composer.available.com.matches", "io", "captain-hook");
                final File packagistRepoRootFile = getRepoResourceFile("composer.available.com.matches", "packages");

                analyzer.setRepositoryId("11");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/repository/p2/io/captain-hook.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
                Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());

                component.setPurl(new PackageURL("pkg:composer/io2/phpunit@v0.0.0"));
                MetaModel metaModel2 = analyzer.analyze(component);

                Assertions.assertNull(metaModel2.getLatestVersion());
                Assertions.assertNull(metaModel2.getPublishedTimestamp());

                // no calls should have been made for non-matching package
                mockClient.verify(
                                request()
                                                .withMethod("GET"),
                                org.mockserver.verify.VerificationTimes.exactly(2));
        }


        /*
         * This case no longer happens in the composer v2 repositories. It now returns a
         * 404 for all examples from #2134
         * - adobe-ims.json
         * - adobe-stock-integration.json
         * - composter-root-update-plugin.json
         * - module-aws-s3.json
         * Leaving it here in case we find a different package triggering this
         * behaviour.
         */
        @Test
        void testAnalyzerGetsUnexpectedResponseContentCausingLatestVersionBeingNull() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/magento/adobe-ims@v1.0.0"));
                final File packagistFile = getPackageResourceFile("repo.packagist.org.v1", "magento", "adobe-ims");
                final File packagistRepoRootFile = getRepoResourceFile("repo.packagist.org.v1", "packages");

                analyzer.setRepositoryId("10");
                @SuppressWarnings("resource")
                MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/packages.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistRepoRootFile)));

                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                mockClient.when(
                                request()
                                                .withMethod("GET")
                                                .withPath("/p/magento/adobe-ims.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json")
                                                                .withBody(getTestData(packagistFile)));

                analyzer.analyze(component);
                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertNull(metaModel.getLatestVersion());
        }

        @Test
        void testAnalyzerGetsUnexpectedResponseContent404() throws Exception {
                Component component = new Component();
                ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

                component.setPurl(new PackageURL("pkg:composer/magento/adobe-ims@v1.0.0"));

                analyzer.setRepositoryId("12");
                analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
                new MockServerClient("localhost", mockServer.getPort())
                                .when(
                                                request()
                                                                .withMethod("GET")
                                                                .withPath("/p2/magento/adobe-ims.json"))
                                .respond(
                                                response()
                                                                .withStatusCode(404)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                                "application/json"));

                analyzer.analyze(component);
                MetaModel metaModel = analyzer.analyze(component);

                Assertions.assertNull(metaModel.getLatestVersion());
        }

        private static File getRepoResourceFile(String repo, String filename) throws Exception {
                String filenameResource = String.format(
                                "unit/tasks/repositories/https---%s-%s.json",
                                repo,
                                filename);
                return getFileResource(filenameResource);
        }

        private static File getPackageResourceFile(String repo, String namespace, String name) throws Exception {
                String filename = String.format(
                                "unit/tasks/repositories/https---%s-%s-%s.json",
                                repo,
                                namespace,
                                name);
                return getFileResource(filename);
        }

        private static File getFileResource(String filename) throws Exception {
                return new File(
                                Thread.currentThread().getContextClassLoader()
                                                .getResource(filename)
                                                .toURI());
        }

        private static byte[] getTestData(File file) throws Exception {
                final FileInputStream fileStream = new FileInputStream(file);
                byte[] data = new byte[(int) file.length()];
                fileStream.read(data);
                fileStream.close();
                return data;
        }
}
