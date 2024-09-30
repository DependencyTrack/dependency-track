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
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

public class NpmMetaAnalyzerTest {

    @Rule
    public final WireMockRule wireMockRule = new WireMockRule(options().dynamicPort());

    @Test
    public void testAnalyzer() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:npm/qunit@2.7.0"));

        NpmMetaAnalyzer analyzer = new NpmMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.NPM, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        //Assert.assertNotNull(metaModel.getPublishedTimestamp()); // todo: not yet supported
    }

    @Test
    public void testWithScopedPackage() {
        stubFor(get(urlPathEqualTo("/-/package/%40angular%2Fcli/dist-tags"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("""
                                {
                                  "latest": "17.1.2",
                                  "next": "17.2.0-next.1",
                                  "v6-lts": "6.2.9",
                                  "v8-lts": "8.3.29",
                                  "v7-lts": "7.3.10",
                                  "v9-lts": "9.1.15",
                                  "v10-lts": "10.2.4",
                                  "v11-lts": "11.2.19",
                                  "v12-lts": "12.2.18",
                                  "v13-lts": "13.3.11",
                                  "v14-lts": "14.2.13",
                                  "v15-lts": "15.2.10",
                                  "v16-lts": "16.2.12"
                                }
                                """)));

        final var component = new Component();
        component.setPurl("pkg:npm/%40angular/cli@17.1.1");

        final var analyzer = new NpmMetaAnalyzer();
        analyzer.setRepositoryBaseUrl(wireMockRule.baseUrl());

        assertThat(analyzer.isApplicable(component)).isTrue();

        final MetaModel metaModel = analyzer.analyze(component);
        assertThat(metaModel).isNotNull();
        assertThat(metaModel.getLatestVersion()).isEqualTo("17.1.2");
    }

    @Test // https://github.com/DependencyTrack/dependency-track/pull/3357#issuecomment-1928690246
    public void testWithSpecialCharactersInPackageName() {
        stubFor(get(urlPathEqualTo("/-/package/jquery%20joyride%20plugin%20/dist-tags"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withBody("""
                                "Not Found"
                                """)));

        final var component = new Component();
        component.setPurl("pkg:npm/jquery%20joyride%20plugin%20@2.1");

        final var analyzer = new NpmMetaAnalyzer();
        analyzer.setRepositoryBaseUrl(wireMockRule.baseUrl());

        assertThat(analyzer.isApplicable(component)).isTrue();

        final MetaModel metaModel = analyzer.analyze(component);
        assertThat(metaModel).isNotNull();
        assertThat(metaModel.getLatestVersion()).isNull();
    }

}
