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
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.matching.RequestPatternBuilder;
import org.apache.http.HttpHeaders;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.text.SimpleDateFormat;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

@WireMockTest
class ComposerMetaAnalyzerTest {

    private WireMockRuntimeInfo wmRuntimeInfo;

    @BeforeEach
    void setUp(WireMockRuntimeInfo wmRuntimeInfo) {
        this.wmRuntimeInfo = wmRuntimeInfo;
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
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/p/monolog/monolog.json", getTestData(packagistFile));

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
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/p2/typo3/class-alias-loader.json", getTestData(packagistFile));

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
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl() + "/therepo");

        stubJson("/therepo/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/therepo/p2/dummyspace/base.json", null);

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("1.18.0", metaModel.getLatestVersion());
        Assertions.assertNull(metaModel.getPublishedTimestamp());

        verify(1, getRequestedFor(urlPathEqualTo("/therepo/packages.json")));
        verify(0, getRequestedFor(urlPathEqualTo("/therepo/p2/dummyspace/base.json")));
        verify(1, RequestPatternBuilder.allRequests());

        component.setPurl(new PackageURL("pkg:composer/something/something@v1.1.0"));
        MetaModel metaModel2 = analyzer.analyze(component);

        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());

        // no extra calls should have been made
        verify(1, getRequestedFor(urlPathEqualTo("/therepo/packages.json")));
        verify(0, getRequestedFor(urlPathEqualTo("/therepo/p2/dummyspace/base.json")));
        verify(1, RequestPatternBuilder.allRequests());
    }

    @Test
    void testAnalyzerIncludesAndRepoPath() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/space/cowboy@v1.1.0"));
        final File packagistRepoRootFile = getRepoResourceFile("composer.include.com.userpass", "packages");
        final File packagistFile = getPackageResourceFile("composer.include.com.userpass", "space", "cowboy");

        analyzer.setRepositoryId("4");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl() + "/user:pass/");

        stubJson("/user:pass/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("2.3.8", metaModel.getLatestVersion());
        // Timestamps are in invalid format for this repo
        Assertions.assertNull(metaModel.getPublishedTimestamp());

        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")));
        verify(2, RequestPatternBuilder.allRequests());

        component.setPurl(new PackageURL("pkg:composer/something/something@v1.1.0"));
        MetaModel metaModel2 = analyzer.analyze(component);

        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());

        // no extra calls should have been made
        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")));
        verify(2, RequestPatternBuilder.allRequests());
    }

    @Test
    void testAnalyzerIncludesWithMetadataUrl() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/space/cowboy@v1.1.0"));
        final File packagistRepoRootFile = getRepoResourceFile("composer.include.com.metadata", "packages");
        final File packagistFile = getPackageResourceFile("composer.include.com.metadata", "space", "cowboy");

        analyzer.setRepositoryId("5");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl() + "/user:pass/");

        stubJson("/user:pass/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json", null);
        stubJson("/user:pass/p2/space/cowboy.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("6.6.6", metaModel.getLatestVersion());
        Assertions.assertNull(metaModel.getPublishedTimestamp());

        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/packages.json")));
        verify(0, getRequestedFor(urlPathEqualTo("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/p2/space/cowboy.json")));
        verify(2, RequestPatternBuilder.allRequests());

        component.setPurl(new PackageURL("pkg:composer/something/something@v1.1.0"));
        MetaModel metaModel2 = analyzer.analyze(component);

        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());

        // no extra calls should have been made, only a metadata call as those are not
        // cached
        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/packages.json")));
        verify(0, getRequestedFor(urlPathEqualTo("/user:pass/user:pass/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/user:pass/p2/space/cowboy.json")));
        verify(3, RequestPatternBuilder.allRequests());
    }

    @Test
    void testAnalyzerCacheOfRoot() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/typo3/class-alias-loader@v1.1.0"));
        final File packagistFile = getPackageResourceFile("repo.packagist.org", "typo3", "class-alias-loader");
        final File packagistRepoRootFile = getRepoResourceFile("repo.packagist.org", "packages");

        analyzer.setRepositoryId("6");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/p2/typo3/class-alias-loader.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
        Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/p2/typo3/class-alias-loader.json")));

        analyzer.analyze(component);
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(2, getRequestedFor(urlPathEqualTo("/p2/typo3/class-alias-loader.json")));
    }

    @Test
    void testAnalyzerEmptyRoot() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/empty/root@v1.1.0"));
        final File packagistRepoRootFile = getRepoResourceFile("repo.empty.org", "packages");

        analyzer.setRepositoryId("7");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));

        MetaModel metaModel = analyzer.analyze(component);
        Assertions.assertNull(metaModel.getLatestVersion());
        Assertions.assertNull(metaModel.getPublishedTimestamp());

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));

        MetaModel metaModel2 = analyzer.analyze(component);
        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
    }

    @Test
    void testAnalyzerDrupalV2NoTimeWithAvailablePackagePatterns() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/drupal/mollie@v2.0.0"));
        final File packagistFile = getPackageResourceFile("packages.drupal.org", "drupal", "mollie");
        final File packagistRepoRootFile = getRepoResourceFile("packages.drupal.org", "packages");

        analyzer.setRepositoryId("8");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/files/packages/8/p2/drupal/mollie.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("2.2.1", metaModel.getLatestVersion());
        Assertions.assertNull(metaModel.getPublishedTimestamp());

        component.setPurl(new PackageURL("pkg:composer/phpunit/phpunit@v2.0.0"));
        MetaModel metaModel2 = analyzer.analyze(component);

        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());

        // no calls should have been made for non-matching package
        verify(2, getRequestedFor(anyUrl()));
    }

    @Test
    void testAnalyzerAvailablePackages() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/io/captain-hook@v0.0.0"));
        final File packagistFile = getPackageResourceFile("composer.available.com", "io", "captain-hook");
        final File packagistRepoRootFile = getRepoResourceFile("composer.available.com", "packages");

        analyzer.setRepositoryId("9");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/repository/p2/io/captain-hook.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
        Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());

        component.setPurl(new PackageURL("pkg:composer/phpunit/phpunit@v0.0.0"));
        MetaModel metaModel2 = analyzer.analyze(component);

        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());

        // no calls should have been made for non-matching package
        verify(2, getRequestedFor(anyUrl()));
    }

    @Test
    void testAnalyzerNotInAvailablePackagesAndMatchingLogic() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/io/captain-hook@v0.0.0"));
        final File packagistFile = getPackageResourceFile("composer.available.com.matches", "io", "captain-hook");
        final File packagistRepoRootFile = getRepoResourceFile("composer.available.com.matches", "packages");

        analyzer.setRepositoryId("11");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/repository/p2/io/captain-hook.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("v1.2.0", metaModel.getLatestVersion());
        Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"), metaModel.getPublishedTimestamp());

        component.setPurl(new PackageURL("pkg:composer/io2/phpunit@v0.0.0"));
        MetaModel metaModel2 = analyzer.analyze(component);

        Assertions.assertNull(metaModel2.getLatestVersion());
        Assertions.assertNull(metaModel2.getPublishedTimestamp());

        // no calls should have been made for non-matching package
        verify(2, getRequestedFor(anyUrl()));
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
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/p/magento/adobe-ims.json", getTestData(packagistFile));

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
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubFor(get(urlPathEqualTo("/p2/magento/adobe-ims.json"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")));

        analyzer.analyze(component);
        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertNull(metaModel.getLatestVersion());
    }

    @Test
    void testAnalyzerHandlesArrayEntryMetadata() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/galaxy/cow@v1.1.0"));

        final File packagistRepoRootFile = getRepoResourceFile("composer.include.com.metadata", "packages");
        final File packagistFile = getPackageResourceFile("composer.include.com.metadata", "galaxy", "cow-arrayentry");

        analyzer.setRepositoryId("13");
        analyzer.setRepositoryBaseUrl(wmRuntimeInfo.getHttpBaseUrl());

        stubJson("/packages.json", getTestData(packagistRepoRootFile));
        stubJson("/p2/galaxy/cow.json", getTestData(packagistFile));

        MetaModel metaModel = analyzer.analyze(component);

        Assertions.assertEquals("9.9.9", metaModel.getLatestVersion());
        Assertions.assertEquals(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX")
                .parse("2025-01-01 00:00:00 Z"), metaModel.getPublishedTimestamp());
    }

    private static void stubJson(String path, byte[] body) {
        var response = aResponse()
                .withStatus(200)
                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        if (body != null) {
            response = response.withBody(body);
        }
        stubFor(get(urlPathEqualTo(path)).willReturn(response));
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
