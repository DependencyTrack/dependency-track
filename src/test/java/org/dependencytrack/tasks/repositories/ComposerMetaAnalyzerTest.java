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
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import java.io.File;
import java.io.FileInputStream;
import java.text.SimpleDateFormat;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class ComposerMetaAnalyzerTest {

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
        component.setPurl(new PackageURL("pkg:composer/phpunit/phpunit@1.0.0"));

        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.COMPOSER, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerFindsVersionWithLeadingV() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/typo3/class-alias-loader@v1.1.0"));
        final File packagistFile = getResourceFile("typo3", "class-alias-loader");

        analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
        new MockServerClient("localhost", mockServer.getPort())
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/p2/typo3/class-alias-loader.json")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody(getTestData(packagistFile))
                );

        analyzer.analyze(component);

        MetaModel metaModel = analyzer.analyze(component);

        Assert.assertEquals("v1.2.0", metaModel.getLatestVersion());
        Assert.assertEquals(
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss XXX").parse("2024-10-11 08:11:39 Z"),
                metaModel.getPublishedTimestamp()
        );
    }

    /*
     * This case no longer happens in the composer v2 repositories. It now returns a 404 for all examples from #2134
     * - adobe-ims.json
     * - adobe-stock-integration.json
     * - composter-root-update-plugin.json
     * - module-aws-s3.json
     * Leaving it here in case we find a different package triggering this behaviour.

    @Test
    public void testAnalyzerGetsUnexpectedResponseContentCausingLatestVersionBeingNull() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/magento/adobe-ims@v1.0.0"));
        final File packagistFile = getResourceFile("magento", "adobe-ims");

        analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
        new MockServerClient("localhost", mockServer.getPort())
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/p2/magento/adobe-ims.json")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody(getTestData(packagistFile))
                );

        analyzer.analyze(component);
        MetaModel metaModel = analyzer.analyze(component);

        Assert.assertNull(metaModel.getLatestVersion());
    }
     */

     @Test
    public void testAnalyzerGetsUnexpectedResponseContent404() throws Exception {
        Component component = new Component();
        ComposerMetaAnalyzer analyzer = new ComposerMetaAnalyzer();

        component.setPurl(new PackageURL("pkg:composer/magento/adobe-ims@v1.0.0"));

        analyzer.setRepositoryBaseUrl(String.format("http://localhost:%d", mockServer.getPort()));
        new MockServerClient("localhost", mockServer.getPort())
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/p2/magento/adobe-ims.json")
                )
                .respond(
                        response()
                                .withStatusCode(404)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                );

        analyzer.analyze(component);
        MetaModel metaModel = analyzer.analyze(component);

        Assert.assertNull(metaModel.getLatestVersion());
    }


    private static File getResourceFile(String namespace, String name) throws Exception{
        return new File(
                Thread.currentThread().getContextClassLoader()
                        .getResource(String.format(
                                "unit/tasks/repositories/https---repo.packagist.org-p2-%s-%s.json",
                                namespace,
                                name
                        ))
                        .toURI()
        );
    }

    private static byte[] getTestData(File file) throws Exception {
        final FileInputStream fileStream = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fileStream.read(data);
        fileStream.close();
        return data;
    }
}
