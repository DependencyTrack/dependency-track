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

public class PortfolioMetricsTest {

    @Test
    public void testId() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setId(111L);
        Assert.assertEquals(111L, metric.getId());
    }

    @Test
    public void testCritical() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setCritical(10);
        Assert.assertEquals(10, metric.getCritical());
    }

    @Test
    public void testHigh() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setHigh(9);
        Assert.assertEquals(9, metric.getHigh());
    }

    @Test
    public void testMedium() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setMedium(8);
        Assert.assertEquals(8, metric.getMedium());
    }

    @Test
    public void testLow() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setLow(7);
        Assert.assertEquals(7, metric.getLow());
    }

    @Test
    public void testUnassigned() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setUnassigned(9191);
        Assert.assertEquals(9191, metric.getUnassigned());
    }

    @Test
    public void testVulnerabilities() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setVulnerabilities(6);
        Assert.assertEquals(6, metric.getVulnerabilities());
    }

    @Test
    public void testProjects() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setProjects(99);
        Assert.assertEquals(99, metric.getProjects());
    }

    @Test
    public void testVulnerableProjects() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setVulnerableProjects(98);
        Assert.assertEquals(98, metric.getVulnerableProjects());
    }

    @Test
    public void testComponents() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setComponents(97);
        Assert.assertEquals(97, metric.getComponents());
    }

    @Test
    public void testVulnerableComponents() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setVulnerableComponents(96);
        Assert.assertEquals(96, metric.getVulnerableComponents());
    }

    @Test
    public void testSuppressed() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setSuppressed(5);
        Assert.assertEquals(5, metric.getSuppressed());
    }

    @Test
    public void testFindingsTotal() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setFindingsTotal(4);
        Assert.assertEquals(4, metric.getFindingsTotal());
    }

    @Test
    public void testFindingsAudited() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setFindingsAudited(3);
        Assert.assertEquals(3, metric.getFindingsAudited());
    }

    @Test
    public void testFindingsUnaudited() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setFindingsUnaudited(2);
        Assert.assertEquals(2, metric.getFindingsUnaudited());
    }

    @Test
    public void testInheritedRiskScore() {
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setInheritedRiskScore(1000);
        Assert.assertEquals(1000, metric.getInheritedRiskScore(), 0);
    }

    @Test
    public void testFirstOccurrence() {
        Date date = new Date();
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setFirstOccurrence(date);
        Assert.assertEquals(date, metric.getFirstOccurrence());
    }

    @Test
    public void testLastOccurrence() {
        Date date = new Date();
        PortfolioMetrics metric = new PortfolioMetrics();
        metric.setLastOccurrence(date);
        Assert.assertEquals(date, metric.getLastOccurrence());
    }
}
