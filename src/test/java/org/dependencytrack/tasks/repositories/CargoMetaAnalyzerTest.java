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

public class CargoMetaAnalyzerTest {

    @Test
    public void testAnalyzerForRand() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:cargo/rand@0.7.2"));

        CargoMetaAnalyzer analyzer = new CargoMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.CARGO, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion(metaModel.getLatestVersion()));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("0.7.1", metaModel.getLatestVersion()));
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }

    @Test
    public void testAnalyzerForBincode() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:cargo/bincode@1.3.0"));

        CargoMetaAnalyzer analyzer = new CargoMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.CARGO, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion(metaModel.getLatestVersion()));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("1.3.2", metaModel.getLatestVersion()));
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }
}
