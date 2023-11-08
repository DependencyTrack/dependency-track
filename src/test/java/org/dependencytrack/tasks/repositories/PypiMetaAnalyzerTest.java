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
import org.dependencytrack.util.ComponentVersion;
import org.junit.Assert;
import org.junit.Test;
import com.github.packageurl.PackageURL;

public class PypiMetaAnalyzerTest {

    @Test
    public void testAnalyzerForFlask() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:pypi/Flask@1.0.0"));

        PypiMetaAnalyzer analyzer = new PypiMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.PYPI, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(ComponentVersion.isStableVersion(metaModel.getLatestVersion()));
        Assert.assertTrue(ComponentVersion.compareVersions("2.2.2", metaModel.getLatestVersion()) < 0);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerForNumPi() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:pypi/NumPi@1.0.0"));

        PypiMetaAnalyzer analyzer = new PypiMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.PYPI, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(ComponentVersion.isStableVersion(metaModel.getLatestVersion()));
        Assert.assertTrue(metaModel.getLatestVersion().startsWith("0") || ComponentVersion.compareVersions("0.3.0", metaModel.getLatestVersion()) < 0); // 0 is considered unstable in SemVer
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }
}
