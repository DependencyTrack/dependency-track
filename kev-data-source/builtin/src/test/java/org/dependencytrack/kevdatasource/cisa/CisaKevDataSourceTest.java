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
package org.dependencytrack.kevdatasource.cisa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class CisaKevDataSourceTest {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    @Test
    void shouldParseCisaKevFeed(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlEqualTo("/kev.json")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(/* language=JSON */ """
                        {
                          "vulnerabilities": [
                            {
                              "cveID": "CVE-2021-44228",
                              "dateAdded": "2021-12-10",
                              "shortDescription": "Log4Shell",
                              "requiredAction": "Apply updates",
                              "knownRansomwareCampaignUse": "Known"
                            },
                            {
                              "cveID": "CVE-2021-45046",
                              "dateAdded": "2021-12-15",
                              "shortDescription": "Follow-up",
                              "requiredAction": "Apply updates",
                              "knownRansomwareCampaignUse": "Unknown"
                            }
                          ]
                        }
                        """)));

        final var dataSource = new CisaKevDataSource(
                HttpClient.newHttpClient(),
                objectMapper,
                URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/kev.json"));

        assertThat(dataSource).toIterable().satisfiesExactly(
                first -> {
                    assertThat(first.vulnSource()).isEqualTo("NVD");
                    assertThat(first.vulnId()).isEqualTo("CVE-2021-44228");
                    assertThat(first.publishedAt()).isEqualTo(Instant.parse("2021-12-10T00:00:00Z"));
                    assertThat(first.requiredAction()).isEqualTo("Apply updates");
                    assertThat(first.knownRansomware()).isTrue();
                    assertThat(first.description()).isEqualTo("Log4Shell");
                    assertThat(first.raw().path("cveID").asText()).isEqualTo("CVE-2021-44228");
                },
                second -> {
                    assertThat(second.vulnId()).isEqualTo("CVE-2021-45046");
                    assertThat(second.knownRansomware()).isNull();
                });
    }

}
