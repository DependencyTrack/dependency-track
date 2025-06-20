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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

class AnalysisTest {

    @Test
    void testId() {
        Analysis analysis = new Analysis();
        analysis.setId(111L);
        Assertions.assertEquals(111L, analysis.getId());
    }

    @Test
    void testComponent() {
        Project project = new Project();
        Component component = new Component();
        component.setProject(project);
        Analysis analysis = new Analysis();
        analysis.setComponent(component);
        Assertions.assertEquals(component, analysis.getComponent());
        Assertions.assertEquals(project, analysis.getProject());
        Assertions.assertEquals(project, analysis.getComponent().getProject());
    }

    @Test
    void testVulnerability() {
        Vulnerability vuln = new Vulnerability();
        Analysis analysis = new Analysis();
        analysis.setVulnerability(vuln);
        Assertions.assertEquals(vuln, analysis.getVulnerability());
    }

    @Test
    void testAnalysisState() {
        Analysis analysis = new Analysis();
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        Assertions.assertEquals(AnalysisState.EXPLOITABLE, analysis.getAnalysisState());
    }

    @Test
    void testGetAnalysisComments() {
        List<AnalysisComment> comments = new ArrayList<>();
        AnalysisComment comment = new AnalysisComment();
        comments.add(comment);
        Analysis analysis = new Analysis();
        analysis.setAnalysisComments(comments);
        Assertions.assertEquals(1, analysis.getAnalysisComments().size());
        Assertions.assertEquals(comment, analysis.getAnalysisComments().get(0));
    }

    @Test
    void testSuppressed() {
        Analysis analysis = new Analysis();
        analysis.setSuppressed(true);
        Assertions.assertTrue(analysis.isSuppressed());
        analysis.setSuppressed(false);
        Assertions.assertFalse(analysis.isSuppressed());
    }
}
