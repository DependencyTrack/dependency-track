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

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.Assert;
import org.junit.Test;

public class NugetMetaAnalyzerTest {

    //@Test
    /*
     * Noticed that Microsoft NuGet is broken for package 3.13.0, which as of this moment, is the latest
     * version available. However, the registration3 API returns a 404 when making queries for it and the call
     * to index.json for the nuget package returns 3.12.0 as the latest version. This is breaking DT unit tests.
     * Commenting out for now.
     */
    public void testAnalyzer() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:nuget/NUnit@3.8.0"));

        NugetMetaAnalyzer analyzer = new NugetMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.NUGET, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertNotNull(metaModel.getPublishedTimestamp());
    }
}
