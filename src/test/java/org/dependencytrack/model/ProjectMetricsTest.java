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

class ProjectMetricsTest {

    @Test
    void testId() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setId(111L);
        Assertions.assertEquals(111L, metric.getId());
    }

    @Test
    void testCritical() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setCritical(10);
        Assertions.assertEquals(10, metric.getCritical());
    }

    @Test
    void testHigh() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setHigh(9);
        Assertions.assertEquals(9, metric.getHigh());
    }

    @Test
    void testMedium() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setMedium(8);
        Assertions.assertEquals(8, metric.getMedium());
    }

    @Test
    void testLow() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setLow(7);
        Assertions.assertEquals(7, metric.getLow());
    }

    @Test
    void testUnassigned() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setUnassigned(9191);
        Assertions.assertEquals(9191, metric.getUnassigned());
    }

    @Test
    void testVulnerabilities() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setVulnerabilities(6);
        Assertions.assertEquals(6, metric.getVulnerabilities());
    }

    @Test
    void testComponents() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setComponents(97);
        Assertions.assertEquals(97, metric.getComponents());
    }

    @Test
    void testVulnerableComponents() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setVulnerableComponents(96);
        Assertions.assertEquals(96, metric.getVulnerableComponents());
    }

    @Test
    void testSuppressed() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setSuppressed(5);
        Assertions.assertEquals(5, metric.getSuppressed());
    }

    @Test
    void testFindingsTotal() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setFindingsTotal(4);
        Assertions.assertEquals(4, metric.getFindingsTotal());
    }

    @Test
    void testFindingsAudited() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setFindingsAudited(3);
        Assertions.assertEquals(3, metric.getFindingsAudited());
    }

    @Test
    void testFindingsUnaudited() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setFindingsUnaudited(2);
        Assertions.assertEquals(2, metric.getFindingsUnaudited());
    }

    @Test
    void testInheritedRiskScore() {
        ProjectMetrics metric = new ProjectMetrics();
        metric.setInheritedRiskScore(1000);
        Assertions.assertEquals(1000, metric.getInheritedRiskScore(), 0);
    }

    @Test
    void testFirstOccurrence() {
        Date date = new Date();
        ProjectMetrics metric = new ProjectMetrics();
        metric.setFirstOccurrence(date);
        Assertions.assertEquals(date, metric.getFirstOccurrence());
    }

    @Test
    void testLastOccurrence() {
        Date date = new Date();
        ProjectMetrics metric = new ProjectMetrics();
        metric.setLastOccurrence(date);
        Assertions.assertEquals(date, metric.getLastOccurrence());
    }
} 
