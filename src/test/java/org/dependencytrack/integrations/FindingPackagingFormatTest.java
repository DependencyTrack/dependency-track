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
package org.dependencytrack.integrations;

import alpine.Config;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;

public class FindingPackagingFormatTest extends PersistenceCapableTest {

    @Test
    public void wrapperTest() {
        final Project project = qm.createProject("Test", "Sample project", "1.0", null, null, null, true, false);

        var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.2.3");
        componentA = qm.createComponent(componentA, false);

        var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("3.2.1");
        qm.createComponent(componentB, false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setInternalId("INTERNAL-001");
        vulnAlias.setCveId("CVE-123");
        qm.synchronizeVulnerabilityAlias(vulnAlias);

        qm.addVulnerability(vuln, componentA, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var fpf = new FindingPackagingFormat(project.getUuid(), qm.getFindings(project));

        assertThatJson(fpf.getDocument())
                .withMatcher("appVersion", equalTo(Config.getInstance().getApplicationVersion()))
                .withMatcher("timestamp", matchesPattern("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuidA", equalTo(componentA.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .withMatcher("matrix", equalTo("%s:%s:%s".formatted(project.getUuid(), componentA.getUuid(), vuln.getUuid())))
                .isEqualTo("""
                        {
                          "version": "1.2",
                          "meta": {
                            "application": "Dependency-Track",
                            "version": "${json-unit.matches:appVersion}",
                            "timestamp": "${json-unit.matches:timestamp}"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "Test",
                            "version": "1.0",
                            "description": "Sample project"
                          },
                          "findings": [
                            {
                              "component": {
                                "uuid": "${json-unit.matches:componentUuidA}",
                                "name": "acme-lib-a",
                                "version": "1.2.3",
                                "project": "${json-unit.matches:projectUuid}"
                              },
                              "attribution": {
                                "analyzerIdentity": "INTERNAL_ANALYZER",
                                "attributedOn": "${json-unit.matches:timestamp}"
                              },
                              "vulnerability": {
                                "uuid": "${json-unit.matches:vulnUuid}",
                                "vulnId": "INTERNAL-001",
                                "source": "INTERNAL",
                                "aliases": [
                                  {
                                    "cveId": "CVE-123"
                                  }
                                ],
                                "severity": "HIGH",
                                "severityRank": 1
                              },
                              "analysis": {
                                "isSuppressed": false
                              },
                              "matrix": "${json-unit.matches:matrix}"
                            }
                          ]
                        }
                        """);
    }
}
