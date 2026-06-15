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
package org.dependencytrack.e2e;

import org.dependencytrack.e2e.api.model.BomUploadRequest;
import org.dependencytrack.e2e.api.model.CreateVulnerabilityRequest;
import org.dependencytrack.e2e.api.model.CreateVulnerabilityRequest.AffectedComponent;
import org.dependencytrack.e2e.api.model.EventProcessingResponse;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.Project;
import org.dependencytrack.e2e.api.model.VexSubmitRequest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class OwaspRatingFromVexE2ET extends AbstractE2ET {

    @Test
    void shouldSurfaceOwaspRatingFromVexInFindings() throws Exception {
        apiClient.createVulnerability(
                new CreateVulnerabilityRequest(
                        "INT-001",
                        "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
                        null,
                        List.of(new AffectedComponent("PURL", "pkg:maven/commons-io/commons-io@2.11.0", "EXACT"))));

        final byte[] bomBytes = getClass().getResourceAsStream("/dtrack-apiserver-4.5.0.bom.json").readAllBytes();
        final EventTokenResponse bomUpload = apiClient.uploadBom(
                new BomUploadRequest(
                        "foo",
                        "bar",
                        true,
                        Base64.getEncoder().encodeToString(bomBytes)));
        awaitProcessed("BOM processing", bomUpload.token());

        final Project project = apiClient.lookupProject("foo", "bar");

        assertThat(apiClient.getFindings(project.uuid(), true)).anySatisfy(finding -> {
            assertThat(finding.vulnerability().vulnId()).isEqualTo("INT-001");
            assertThat(finding.vulnerability().owaspRRVector()).isNull();
        });

        final EventTokenResponse vexUploadResponse = apiClient.uploadVex(
                new VexSubmitRequest(
                        project.uuid().toString(),
                        null,
                        null,
                        Base64.getEncoder().encodeToString(/* language=JSON */ """
                                {
                                  "bomFormat": "CycloneDX",
                                  "specVersion": "1.4",
                                  "version": 1,
                                  "metadata": {
                                    "component": {
                                      "bom-ref": "project",
                                      "type": "application",
                                      "name": "foo",
                                      "version": "bar"
                                    }
                                  },
                                  "vulnerabilities": [
                                    {
                                      "id": "INT-001",
                                      "source": {
                                        "name": "INTERNAL"
                                      },
                                      "ratings": [
                                        {
                                          "method": "OWASP",
                                          "vector": "OWASP/SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3",
                                          "score": 7.5
                                        }
                                      ],
                                      "affects": [
                                        {
                                          "ref": "project"
                                        }
                                      ]
                                    }
                                  ]
                                }
                                """.getBytes(StandardCharsets.UTF_8))));
        awaitProcessed("VEX processing", vexUploadResponse.token());

        await("OWASP rating applied to finding")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> assertThat(apiClient.getFindings(project.uuid(), true)).anySatisfy(finding -> {
                    assertThat(finding.vulnerability().vulnId()).isEqualTo("INT-001");
                    assertThat(finding.vulnerability().owaspRRVector()).isEqualTo(
                            "OWASP/SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3");
                    assertThat(finding.vulnerability().owaspBusinessImpactScore()).isEqualTo(7.5);
                    assertThat(finding.vulnerability().owaspLikelihoodScore()).isEqualTo(7.5);
                    assertThat(finding.vulnerability().owaspTechnicalImpactScore()).isEqualTo(7.5);
                    assertThat(finding.vulnerability().severity()).isEqualTo("HIGH");
                }));
    }

    private void awaitProcessed(String description, String token) {
        await(description)
                .atMost(Duration.ofSeconds(15))
                .pollDelay(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    final EventProcessingResponse processing = apiClient.isEventBeingProcessed(token);
                    assertThat(processing.processing()).isFalse();
                });
    }

}
