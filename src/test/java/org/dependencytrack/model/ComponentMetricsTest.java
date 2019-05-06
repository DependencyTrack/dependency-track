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

public class ComponentMetricsTest {

    @Test
    public void testId() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setId(111L);
        Assert.assertEquals(111L, metric.getId());
    }

    @Test
    public void testComponent() {
        Component component = new Component();
        ComponentMetrics metric = new ComponentMetrics();
        metric.setComponent(component);
        Assert.assertEquals(component, metric.getComponent());
    }

    @Test
    public void testCritical() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setCritical(10);
        Assert.assertEquals(10, metric.getCritical());
    }

    @Test
    public void testHigh() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setHigh(9);
        Assert.assertEquals(9, metric.getHigh());
    } 

    @Test
    public void testMedium() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setMedium(8);
        Assert.assertEquals(8, metric.getMedium());
    }

    @Test
    public void testLow() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setLow(7);
        Assert.assertEquals(7, metric.getLow());
    } 

    @Test
    public void testVulnerabilities() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setVulnerabilities(6);
        Assert.assertEquals(6, metric.getVulnerabilities());
    }

    @Test
    public void testSuppressed() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setSuppressed(5);
        Assert.assertEquals(5, metric.getSuppressed());
    } 

    @Test
    public void testFindingsTotal() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setFindingsTotal(4);
        Assert.assertEquals(4, metric.getFindingsTotal());
    }

    @Test
    public void testFindingsAudited() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setFindingsAudited(3);
        Assert.assertEquals(3, metric.getFindingsAudited());
    }

    @Test
    public void testFindingsUnaudited() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setFindingsUnaudited(2);
        Assert.assertEquals(2, metric.getFindingsUnaudited());
    }

    @Test
    public void testInheritedRiskScore() {
        ComponentMetrics metric = new ComponentMetrics();
        metric.setInheritedRiskScore(1000);
        Assert.assertEquals(1000, metric.getInheritedRiskScore(), 0);
    }

    @Test
    public void testFirstOccurrence() {
        Date date = new Date();
        ComponentMetrics metric = new ComponentMetrics();
        metric.setFirstOccurrence(date);
        Assert.assertEquals(date, metric.getFirstOccurrence());
    }

    @Test
    public void testLastOccurrence() {
        Date date = new Date();
        ComponentMetrics metric = new ComponentMetrics();
        metric.setLastOccurrence(date);
        Assert.assertEquals(date, metric.getLastOccurrence());
    }
} 
