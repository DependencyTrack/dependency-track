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

import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.Assert;
import org.junit.Test;

import com.github.packageurl.PackageURL;

public class GemMetaAnalyzerTest {

    @Test
    public void testAnalyzerForTestUnit() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:gem/test-unit@3.2.0"));

        GemMetaAnalyzer analyzer = new GemMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GEM, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion(metaModel.getLatestVersion()));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("3.0.0", metaModel.getLatestVersion()));
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerForRails() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:gem/rails@3.2.0"));

        GemMetaAnalyzer analyzer = new GemMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GEM, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion(metaModel.getLatestVersion()));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("6.0.0", metaModel.getLatestVersion()));
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }
}
