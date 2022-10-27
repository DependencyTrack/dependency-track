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
package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class AnalysisDecisionChangeTest {

    @Test
    public void testVo() {
        Vulnerability vuln = new Vulnerability();
        Component component = new Component();
        Project project = new Project();
        Analysis analysis = new Analysis();
        AnalysisDecisionChange vo = new AnalysisDecisionChange(vuln, component, project, analysis);
        Assert.assertEquals(vuln, vo.getVulnerability());
        Assert.assertEquals(component, vo.getComponent());
        Assert.assertEquals(project, vo.getProject());
        Assert.assertEquals(analysis, vo.getAnalysis());
    }
}
