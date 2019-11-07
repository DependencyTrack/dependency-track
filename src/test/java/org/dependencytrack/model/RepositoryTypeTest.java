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
package org.dependencytrack.model;

import com.github.packageurl.PackageURL;
import org.junit.Assert;
import org.junit.Test;

public class RepositoryTypeTest {

    @Test
    public void testEnums() {
        Assert.assertEquals("MAVEN", RepositoryType.MAVEN.name());
        Assert.assertEquals("NPM", RepositoryType.NPM.name());
        Assert.assertEquals("GEM", RepositoryType.GEM.name());
        Assert.assertEquals("PYPI", RepositoryType.PYPI.name());
        Assert.assertEquals("NUGET", RepositoryType.NUGET.name());
        Assert.assertEquals("HEX", RepositoryType.HEX.name());
        Assert.assertEquals("UNSUPPORTED", RepositoryType.UNSUPPORTED.name());
    }

    @Test
    public void testResolveMaven() throws Exception {
        PackageURL purl = new PackageURL("pkg:maven/groupId/artifactId@1.0.0");
        Assert.assertEquals(RepositoryType.MAVEN, RepositoryType.resolve(purl));
    }

    @Test
    public void testResolveNpm() throws Exception {
        PackageURL purl = new PackageURL("pkg:npm/artifact@1.0.0");
        Assert.assertEquals(RepositoryType.NPM, RepositoryType.resolve(purl));
    }

    @Test
    public void testResolveGem() throws Exception {
        PackageURL purl = new PackageURL("pkg:gem/artifact@1.0.0");
        Assert.assertEquals(RepositoryType.GEM, RepositoryType.resolve(purl));
    }

    @Test
    public void testResolvePypi() throws Exception {
        PackageURL purl = new PackageURL("pkg:pypi/artifact@1.0.0");
        Assert.assertEquals(RepositoryType.PYPI, RepositoryType.resolve(purl));
    }

    @Test
    public void testResolveNuget() throws Exception {
        PackageURL purl = new PackageURL("pkg:nuget/artifact@1.0.0");
        Assert.assertEquals(RepositoryType.NUGET, RepositoryType.resolve(purl));
    }

    @Test
    public void testResolveHex() throws Exception {
        PackageURL purl = new PackageURL("pkg:hex/phoenix@1.14.10");
        Assert.assertEquals(RepositoryType.HEX, RepositoryType.resolve(purl));
    }

    @Test
    public void testResolveUnsupported() throws Exception {
        PackageURL purl = new PackageURL("pkg:generic/artifact@1.0.0");
        Assert.assertEquals(RepositoryType.UNSUPPORTED, RepositoryType.resolve(purl));
    }
} 
