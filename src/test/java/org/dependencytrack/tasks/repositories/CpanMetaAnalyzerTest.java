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

import java.util.Date;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.util.ComponentVersion;
import org.junit.Assert;
import org.junit.Test;
import com.github.packageurl.PackageURL;

public class CpanMetaAnalyzerTest {

    @Test
    public void testAnalyzerMoose() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:cpan/Moose@2.2200"));

        CpanMetaAnalyzer analyzer = new CpanMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.CPAN, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(new ComponentVersion("2.2200").compareTo(new ComponentVersion(metaModel.getLatestVersion())) < 0);
        Assert.assertTrue(new Date().compareTo(metaModel.getPublishedTimestamp()) > 0);
    }

    @Test
    public void testAnalyzerFutureQ() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:cpan/Future::Q@0.27"));

        CpanMetaAnalyzer analyzer = new CpanMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.CPAN, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(new ComponentVersion("0.27").compareTo(new ComponentVersion(metaModel.getLatestVersion())) < 0);
        Assert.assertTrue(new Date().compareTo(metaModel.getPublishedTimestamp()) > 0);
    }
}
