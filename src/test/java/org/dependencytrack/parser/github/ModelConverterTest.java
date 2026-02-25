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
package org.dependencytrack.parser.github;

import alpine.common.logging.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.data.Offset.offset;

class ModelConverterTest {

    private final ObjectMapper jsonMapper = new JsonMapper()
            .registerModule(new JavaTimeModule());

    private ModelConverter converter;

    @BeforeEach
    void setUp() {
        converter = new ModelConverter(Logger.getLogger(ModelConverterTest.class));
    }

    @Test
    void testConvertEpssScore() throws Exception {
        // Real values from the GitHub GraphQL API for GHSA-57j2-w4cx-62h2 (CVE-2020-36518):
        //   "percentage": 0.00514  →  exploitation probability (EPSS score, 0.0-1.0)
        //   "percentile": 0.66009  →  relative rank (0.0-1.0, i.e. above 66% of all CVEs)
        //
        // A 0.514% exploitation probability at the 66th percentile is realistic because EPSS
        // scores are heavily skewed toward zero; even a small absolute probability can rank high.
        // If the two fields were accidentally swapped the assertions below would fail with values
        // that are semantically impossible (e.g. 66% exploitation probability).
        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:36Z",
                  "updatedAt": "2024-03-15T00:24:56Z",
                  "epss": {
                    "percentage": 0.00514,
                    "percentile": 0.66009
                  }
                }
                """, SecurityAdvisory.class);

        final Vulnerability vuln = converter.convert(advisory);

        assertThat(vuln).isNotNull();
        assertThat(vuln.getEpssScore())
                .as("epssScore must hold the exploitation probability from the 'percentage' JSON field")
                .isNotNull();
        assertThat(vuln.getEpssScore().doubleValue()).isCloseTo(0.00514, offset(0.00001));
        assertThat(vuln.getEpssPercentile())
                .as("epssPercentile must hold the relative rank from the 'percentile' JSON field")
                .isNotNull();
        assertThat(vuln.getEpssPercentile().doubleValue()).isCloseTo(0.66009, offset(0.00001));
    }

    @Test
    void testConvertEpssAbsent() throws Exception {
        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:36Z",
                  "updatedAt": "2024-03-15T00:24:56Z"
                }
                """, SecurityAdvisory.class);

        final Vulnerability vuln = converter.convert(advisory);

        assertThat(vuln).isNotNull();
        assertThat(vuln.getEpssScore()).isNull();
        assertThat(vuln.getEpssPercentile()).isNull();
    }

    @Test
    void testConvertEpssPartialDataPercentileOnly() throws Exception {
        // Only the rank/percentile field is present — epssScore must remain null.
        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:36Z",
                  "updatedAt": "2024-03-15T00:24:56Z",
                  "epss": {
                    "percentile": 0.66009
                  }
                }
                """, SecurityAdvisory.class);

        final Vulnerability vuln = converter.convert(advisory);

        assertThat(vuln).isNotNull();
        assertThat(vuln.getEpssScore()).isNull();
        assertThat(vuln.getEpssPercentile()).isNotNull();
        assertThat(vuln.getEpssPercentile().doubleValue()).isCloseTo(0.66009, offset(0.00001));
    }

    @Test
    void testConvertWithdrawnAdvisoryReturnsNull() throws Exception {
        final var advisory = jsonMapper.readValue(/* language=JSON */ """
                {
                  "ghsaId": "GHSA-57j2-w4cx-62h2",
                  "severity": "HIGH",
                  "publishedAt": "2022-03-12T00:00:00Z",
                  "updatedAt": "2022-08-11T00:00:00Z",
                  "withdrawnAt": "2023-01-01T00:00:00Z"
                }
                """, SecurityAdvisory.class);

        assertThat(converter.convert(advisory)).isNull();
    }

    @Test
    void testConvertSeverityMapping() throws Exception {
        for (final var entry : new Object[][]{
                {"LOW", Severity.LOW},
                {"MODERATE", Severity.MEDIUM},
                {"HIGH", Severity.HIGH},
                {"CRITICAL", Severity.CRITICAL},
        }) {
            final String ghsaSeverity = (String) entry[0];
            final Severity expected = (Severity) entry[1];

            final var advisory = jsonMapper.readValue(/* language=JSON */ """
                    {
                      "ghsaId": "GHSA-57j2-w4cx-62h2",
                      "severity": "%s",
                      "publishedAt": "2022-03-12T00:00:00Z",
                      "updatedAt": "2022-08-11T00:00:00Z"
                    }
                    """.formatted(ghsaSeverity), SecurityAdvisory.class);

            assertThat(converter.convert(advisory).getSeverity())
                    .as("severity for GHSA %s", ghsaSeverity)
                    .isEqualTo(expected);
        }
    }
}
