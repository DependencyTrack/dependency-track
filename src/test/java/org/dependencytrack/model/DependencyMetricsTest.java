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
import java.util.Date;

public class DependencyMetricsTest {

    @Test
    public void testId() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setId(111L);
        Assert.assertEquals(111L, metric.getId());
    }

    @Test
    public void testProject() {
        Project project = new Project();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setProject(project);
        Assert.assertEquals(project, metric.getProject());
    }

    @Test
    public void testComponent() {
        Component component = new Component();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setComponent(component);
        Assert.assertEquals(component, metric.getComponent());
    }

    @Test
    public void testCritical() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setCritical(10);
        Assert.assertEquals(10, metric.getCritical());
    }

    @Test
    public void testHigh() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setHigh(9);
        Assert.assertEquals(9, metric.getHigh());
    }

    @Test
    public void testMedium() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setMedium(8);
        Assert.assertEquals(8, metric.getMedium());
    }

    @Test
    public void testLow() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setLow(7);
        Assert.assertEquals(7, metric.getLow());
    }

    @Test
    public void testUnassigned() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setUnassigned(9191);
        Assert.assertEquals(9191, metric.getUnassigned());
    }

    @Test
    public void testVulnerabilities() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setVulnerabilities(6);
        Assert.assertEquals(6, metric.getVulnerabilities());
    }

    @Test
    public void testSuppressed() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setSuppressed(5);
        Assert.assertEquals(5, metric.getSuppressed());
    }

    @Test
    public void testFindingsTotal() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFindingsTotal(4);
        Assert.assertEquals(4, metric.getFindingsTotal());
    }

    @Test
    public void testFindingsAudited() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFindingsAudited(3);
        Assert.assertEquals(3, metric.getFindingsAudited());
    }

    @Test
    public void testFindingsUnaudited() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFindingsUnaudited(2);
        Assert.assertEquals(2, metric.getFindingsUnaudited());
    }

    @Test
    public void testInheritedRiskScore() {
        DependencyMetrics metric = new DependencyMetrics();
        metric.setInheritedRiskScore(1000);
        Assert.assertEquals(1000, metric.getInheritedRiskScore(), 0);
    }

    @Test
    public void testFirstOccurrence() {
        Date date = new Date();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setFirstOccurrence(date);
        Assert.assertEquals(date, metric.getFirstOccurrence());
    }

    @Test
    public void testLastOccurrence() {
        Date date = new Date();
        DependencyMetrics metric = new DependencyMetrics();
        metric.setLastOccurrence(date);
        Assert.assertEquals(date, metric.getLastOccurrence());
    }
} 
