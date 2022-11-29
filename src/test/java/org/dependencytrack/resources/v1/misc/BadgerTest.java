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
package org.dependencytrack.resources.v1.misc;

import org.apache.commons.io.FileUtils;
import org.dependencytrack.model.ProjectMetrics;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class BadgerTest {

    @Test
    public void generateVulnerabilitiesWithoutMetricsGenerateExpectedSvg() throws Exception {
        Badger badger = new Badger();
        String svg = badger.generateVulnerabilities(null);
        Assert.assertEquals(strip(svg), strip(expectedSvg("project-vulns-nometrics.svg")));
    }

    @Test
    public void generateVulnerabilitiesWithoutVulnerabilitiesGenerateExpectedSvg() throws Exception {
        ProjectMetrics metrics = new ProjectMetrics();
        metrics.setVulnerabilities(0);
        Badger badger = new Badger();
        String svg = badger.generateVulnerabilities(metrics);
        Assert.assertEquals(strip(svg), strip(expectedSvg("project-vulns-none.svg")));
    }

    @Test
    public void generateVulnerabilitiesWithVulnerabilitiesGenerateExpectedSvg() throws Exception {
        ProjectMetrics metrics = new ProjectMetrics();
        metrics.setVulnerabilities(1 + 2 + 3 + 4 + 5);
        metrics.setCritical(1);
        metrics.setHigh(2);
        metrics.setMedium(3);
        metrics.setLow(4);
        metrics.setUnassigned(5);
        Badger badger = new Badger();
        String svg = badger.generateVulnerabilities(metrics);
        Assert.assertEquals(strip(svg), strip(expectedSvg("project-vulns.svg")));
    }

    @Test
    public void generateViolationsWithoutMetricsGenerateExpectedSvg() throws Exception {
        Badger badger = new Badger();
        String svg = badger.generateViolations(null);
        Assert.assertEquals(strip(svg), strip(expectedSvg("project-violations-nometrics.svg")));
    }

    @Test
    public void generateViolationsWithoutViolationsGenerateExpectedSvg() throws Exception {
        ProjectMetrics metrics = new ProjectMetrics();
        metrics.setPolicyViolationsTotal(0);
        Badger badger = new Badger();
        String svg = badger.generateViolations(metrics);
        Assert.assertEquals(strip(svg), strip(expectedSvg("project-violations-none.svg")));
    }

    @Test
    public void generateViolationsWithViolationsGenerateExpectedSvg() throws Exception {
        ProjectMetrics metrics = new ProjectMetrics();
        metrics.setPolicyViolationsTotal(1 + 2 + 3);
        metrics.setPolicyViolationsFail(1);
        metrics.setPolicyViolationsWarn(2);
        metrics.setPolicyViolationsInfo(3);
        Badger badger = new Badger();
        String svg = badger.generateViolations(metrics);
        Assert.assertEquals(strip(svg), strip(expectedSvg("project-violations.svg")));
    }

    private String expectedSvg(String filename) throws Exception {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        URL resource = contextClassLoader.getResource("badge/" + filename);
        if (resource == null) {
            throw new RuntimeException("can't find expected svg filename=" + filename);
        }
        try {
            return FileUtils.readFileToString(new File(resource.toURI()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("can't load expected svg filename=" + filename);
        }
    }

    private static String strip(String svg) {
        return svg
                .trim()
                .replaceAll(" {2}", "")
                .replaceAll("\r\n", "\n");
    }
}