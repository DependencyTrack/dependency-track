/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.dependencycheck.resolver;

import com.github.packageurl.PackageURL;
import org.junit.Assert;
import org.junit.Test;
import org.dependencytrack.parser.dependencycheck.model.Dependency;
import org.dependencytrack.parser.dependencycheck.model.Identifier;

public class PackageURLResolverTest {

    @Test
    public void testMavenIdConformance() {
        PackageURLResolver resolver = new PackageURLResolver();

        Dependency d1 = new Dependency();
        Identifier id1 = new Identifier();
        id1.setType("maven");
        id1.setName("mygroup:myartifact-something-native:1.0.0");
        d1.setIdentifier(id1);
        PackageURL p1 = resolver.resolve(d1);
        Assert.assertEquals("pkg:maven/mygroup/myartifact-something-native@1.0.0", p1.canonicalize());


        Dependency d2 = new Dependency();
        Identifier id2 = new Identifier();
        id2.setType("maven");
        id2.setName("mygroup:myartifact-something-${platform}:1.0.0");
        d2.setIdentifier(id2);
        PackageURL p2 = resolver.resolve(d2);

        Assert.assertNull(p2);
    }

}
