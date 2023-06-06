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
package org.dependencytrack.integrations.kenna;

import alpine.model.IConfigProperty;
import org.apache.commons.io.IOUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_CONNECTOR_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.hamcrest.Matchers.matchesPattern;

public class KennaSecurityUploaderTest extends PersistenceCapableTest {

    @Test
    public void testIntegrationMetadata() {
        KennaSecurityUploader extension = new KennaSecurityUploader();
        Assert.assertEquals("Kenna Security", extension.name());
        Assert.assertEquals("Pushes Dependency-Track findings to Kenna Security", extension.description());
    }

    @Test
    public void testIntegrationEnabledCases() {
        qm.createConfigProperty(
                KENNA_ENABLED.getGroupName(),
                KENNA_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        qm.createConfigProperty(
                KENNA_ENABLED.getGroupName(),
                KENNA_CONNECTOR_ID.getPropertyName(),
                "Dependency-Track (KDI)",
                IConfigProperty.PropertyType.STRING,
                null
        );
        KennaSecurityUploader extension = new KennaSecurityUploader();
        extension.setQueryManager(qm);
        Assert.assertTrue(extension.isEnabled());
    }

    @Test
    public void testIntegrationDisabledCases() {
        KennaSecurityUploader extension = new KennaSecurityUploader();
        extension.setQueryManager(qm);
        Assert.assertFalse(extension.isEnabled());
    }

    @Test
    public void testIntegrationFindings() throws Exception {
        final Project project = qm.createProject("Test", "Sample project", "1.0", null, null, null, true, false);

        qm.createProjectProperty(project, "integrations", "kenna.asset.external_id", "foobar123", IConfigProperty.PropertyType.STRING, null);

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

        final var extension = new KennaSecurityUploader();
        extension.setQueryManager(qm);
        assertThatJson(IOUtils.toString(extension.process(), StandardCharsets.UTF_8))
                .withMatcher("timestamp", matchesPattern("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"))
                .isEqualTo("""
                        {
                          "skip_autoclose": false,
                          "assets": [
                            {
                              "application": "Test 1.0",
                              "external_id": "foobar123",
                              "vulns": [
                                {
                                  "scanner_type": "Dependency-Track",
                                  "scanner_identifier": "INTERNAL-INTERNAL-001",
                                  "last_seen_at": "${json-unit.matches:timestamp}",
                                  "status": "open",
                                  "scanner_score": 7,
                                  "override_score": 70
                                }
                              ]
                            }
                          ],
                          "vuln_defs": [
                            {
                              "scanner_type": "Dependency-Track",
                              "scanner_identifier": "INTERNAL-INTERNAL-001",
                              "name": "INTERNAL-001 (source: INTERNAL)"
                            }
                          ]
                        }
                        """);
    }
}
