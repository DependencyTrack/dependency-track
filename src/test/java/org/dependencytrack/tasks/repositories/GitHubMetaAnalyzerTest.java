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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.Assert;
import org.junit.Test;

import java.util.regex.Pattern;

public class GitHubMetaAnalyzerTest {

    private static final String VERSION_TYPE_PATTERN = "[a-f,0-9]{6,40}";
    @Test
    public void testAnalyzerRelease() throws Exception {
        final var component = new Component();
        component.setPurl(new PackageURL("pkg:github/CycloneDX/cdxgen@v9.8.9"));

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertTrue(metaModel.getLatestVersion().startsWith("v"));
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }
    @Test
    public void testAnalyzerLongCommit() throws Exception{
        final var component = new Component();
        component.setPurl(new PackageURL("pkg:github/CycloneDX/cdxgen@4359dee1b7bd29ee25bc78e358a1254a0277ee96"));
        Pattern version_pattern = Pattern.compile(VERSION_TYPE_PATTERN);

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertTrue(version_pattern.matcher(metaModel.getLatestVersion()).find());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerShortCommit() throws Exception{
        final var component = new Component();
        component.setPurl(new PackageURL("pkg:github/CycloneDX/cdxgen@4359dee"));
        Pattern version_pattern = Pattern.compile(VERSION_TYPE_PATTERN);

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertTrue(version_pattern.matcher(metaModel.getLatestVersion()).find());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerNoVersion() throws Exception{
        final var component = new Component();
        component.setPurl(new PackageURL("pkg:github/CycloneDX/cdxgen"));

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertTrue(metaModel.getLatestVersion().startsWith("v"));
        Assert.assertNull(metaModel.getPublishedTimestamp());
    }
    @Test
    public void testAnalyzerInvalidCommit() throws Exception{
        final var component = new Component();
        component.setPurl(new PackageURL("pkg:github/CycloneDX/cdxgen@0000000"));

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNull(metaModel.getPublishedTimestamp());
    }

        @Test
    public void testAnalyzerInvalidRelease() throws Exception{
        final var component = new Component();
        component.setPurl(new PackageURL("pkg:github/CycloneDX/cdxgen@invalid-release"));

        final var analyzer = new GithubMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GITHUB, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNull(metaModel.getPublishedTimestamp());
    }
}
