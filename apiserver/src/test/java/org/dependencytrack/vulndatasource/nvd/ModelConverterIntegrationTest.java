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
package org.dependencytrack.vulndatasource.nvd;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ModelConverterIntegrationTest {

    @Test
    void shouldSelectPrimaryNvdRatingWhenSecondaryRatingComesFirst() throws Exception {
        final DefCveItem cveItem = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .readValue(/* language=JSON */ """
                        {
                          "cve": {
                            "id": "CVE-2023-2976",
                            "published": "2023-07-05T18:15:14Z",
                            "lastModified": "2026-04-22T20:15:58Z",
                            "descriptions": [],
                            "references": [],
                            "metrics": {
                              "cvssMetricV31": [
                                {
                                  "source": "cna@example.com",
                                  "type": "Secondary",
                                  "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                    "baseScore": 5.5,
                                    "baseSeverity": "MEDIUM"
                                  }
                                },
                                {
                                  "source": "nvd@nist.gov",
                                  "type": "Primary",
                                  "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                    "baseScore": 7.1,
                                    "baseSeverity": "HIGH"
                                  }
                                }
                              ]
                            }
                          }
                        }
                        """, DefCveItem.class);

        final Bom bov = ModelConverter.convert(cveItem);
        final Vulnerability vuln = BovModelConverter.convert(bov, bov.getVulnerabilities(0), true);

        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
        assertThat(vuln.getCvssV3BaseScore()).isEqualByComparingTo("7.1");
    }
}
