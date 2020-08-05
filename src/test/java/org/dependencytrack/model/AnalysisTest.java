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

import org.junit.Assert;
import org.junit.Test;
import java.util.ArrayList;
import java.util.List;

public class AnalysisTest {

    @Test
    public void testId() {
        Analysis analysis = new Analysis();
        analysis.setId(111L);
        Assert.assertEquals(111L, analysis.getId());
    }

    @Test
    public void testComponent() {
        Project project = new Project();
        Component component = new Component();
        component.setProject(project);
        Analysis analysis = new Analysis();
        analysis.setComponent(component);
        Assert.assertEquals(component, analysis.getComponent());
        Assert.assertEquals(project, analysis.getProject());
        Assert.assertEquals(project, analysis.getComponent().getProject());
    }

    @Test
    public void testVulnerability() {
        Vulnerability vuln = new Vulnerability();
        Analysis analysis = new Analysis();
        analysis.setVulnerability(vuln);
        Assert.assertEquals(vuln, analysis.getVulnerability());
    }

    @Test
    public void testAnalysisState() {
        Analysis analysis = new Analysis();
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        Assert.assertEquals(AnalysisState.EXPLOITABLE, analysis.getAnalysisState());
    }

    @Test
    public void testGetAnalysisComments() {
        List<AnalysisComment> comments = new ArrayList<>();
        AnalysisComment comment = new AnalysisComment();
        comments.add(comment);
        Analysis analysis = new Analysis();
        analysis.setAnalysisComments(comments);
        Assert.assertEquals(1, analysis.getAnalysisComments().size());
        Assert.assertEquals(comment, analysis.getAnalysisComments().get(0));
    }

    @Test
    public void testSuppressed() {
        Analysis analysis = new Analysis();
        analysis.setSuppressed(true);
        Assert.assertTrue(analysis.isSuppressed());
        analysis.setSuppressed(false);
        Assert.assertFalse(analysis.isSuppressed());
    }
}
