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

import java.util.Date;

class DependencyMetricsTest {

    @Test
    void testId() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setId(111L);
        Assertions.assertEquals(111L, metric.getId());
    }

    @Test
    void testProject() {
        Project project = new Project();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setProject(project);
        Assertions.assertEquals(project, metric.getProject());
    }

    @Test
    void testComponent() {
        Component component = new Component();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setComponent(component);
        Assertions.assertEquals(component, metric.getComponent());
    }

    @Test
    void testCritical() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setCritical(10);
        Assertions.assertEquals(10, metric.getCritical());
    }

    @Test
    void testHigh() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setHigh(9);
        Assertions.assertEquals(9, metric.getHigh());
    }

    @Test
    void testMedium() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setMedium(8);
        Assertions.assertEquals(8, metric.getMedium());
    }

    @Test
    void testLow() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setLow(7);
        Assertions.assertEquals(7, metric.getLow());
    }

    @Test
    void testUnassigned() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setUnassigned(9191);
        Assertions.assertEquals(9191, metric.getUnassigned());
    }

    @Test
    void testVulnerabilities() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setVulnerabilities(6);
        Assertions.assertEquals(6, metric.getVulnerabilities());
    }

    @Test
    void testSuppressed() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setSuppressed(5);
        Assertions.assertEquals(5, metric.getSuppressed());
    }

    @Test
    void testFindingsTotal() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFindingsTotal(4);
        Assertions.assertEquals(4, metric.getFindingsTotal());
    }

    @Test
    void testFindingsAudited() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFindingsAudited(3);
        Assertions.assertEquals(3, metric.getFindingsAudited());
    }

    @Test
    void testFindingsUnaudited() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFindingsUnaudited(2);
        Assertions.assertEquals(2, metric.getFindingsUnaudited());
    }

    @Test
    void testInheritedRiskScore() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setInheritedRiskScore(1000);
        Assertions.assertEquals(1000, metric.getInheritedRiskScore(), 0);
    }

    @Test
    void testFirstOccurrence() {
        Date date = new Date();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFirstOccurrence(date);
        Assertions.assertEquals(date, metric.getFirstOccurrence());
    }

    @Test
    void testLastOccurrence() {
        Date date = new Date();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setLastOccurrence(date);
        Assertions.assertEquals(date, metric.getLastOccurrence());
    }
} 
