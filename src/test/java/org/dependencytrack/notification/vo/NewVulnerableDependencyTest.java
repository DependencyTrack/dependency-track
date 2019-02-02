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
package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Dependency;
import org.dependencytrack.model.Vulnerability;
import org.junit.Assert;
import org.junit.Test;
import java.util.ArrayList;
import java.util.List;

public class NewVulnerableDependencyTest {

    @Test
    public void testVo() {
        Dependency dependency = new Dependency();
        List<Vulnerability> vulns = new ArrayList<>();
        Vulnerability vuln = new Vulnerability();
        vulns.add(vuln);
        NewVulnerableDependency vo = new NewVulnerableDependency(dependency, vulns);
        Assert.assertEquals(dependency, vo.getDependency());
        Assert.assertEquals(1, vo.getVulnerabilities().size());
        Assert.assertEquals(vuln, vo.getVulnerabilities().get(0));
    }
}
