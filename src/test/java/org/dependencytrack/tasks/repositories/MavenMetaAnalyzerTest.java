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

public class MavenMetaAnalyzerTest {

    @Test
    public void testAnalyzerForJUnit() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:maven/junit/junit@4.12"));

        MavenMetaAnalyzer analyzer = new MavenMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.MAVEN, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(ComponentVersion.compareVersions("4.13.1", metaModel.getLatestVersion()) < 0);
        Assert.assertTrue(ComponentVersion.isStableVersion(metaModel.getLatestVersion()));
        // publishedTimestamp might be set or not
    }

    @Test
    public void testAnalyzerForApacheCamel() throws Exception {
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:maven/org.apache.camel/camel-core@2.21.2"));

        MavenMetaAnalyzer analyzer = new MavenMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.MAVEN, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(ComponentVersion.compareVersions("3.20.1", metaModel.getLatestVersion()) < 0);
        Assert.assertTrue(ComponentVersion.isStableVersion(metaModel.getLatestVersion()));
        // publishedTimestamp might be set or not
    }

    @Test
    public void testAnalyzerForScalaComponent() throws Exception {
        Component component = new Component();

        // Scala packages differ from others in that their name always includes the version of
        // the Scala compiler they were built with.
        component.setPurl(new PackageURL("pkg:maven/com.typesafe.akka/akka-actor_2.13@2.5.23"));

        MavenMetaAnalyzer analyzer = new MavenMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.MAVEN, analyzer.supportedRepositoryType());
        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertTrue(ComponentVersion.compareVersions("2.6.0", metaModel.getLatestVersion()) < 0);
        Assert.assertTrue(ComponentVersion.isStableVersion(metaModel.getLatestVersion()));
        // publishedTimestamp might be set or not
    }

}
