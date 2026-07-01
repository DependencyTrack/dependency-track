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
package org.dependencytrack.kevdatasource.enisa;

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
class EnisaKevDataSourceTest {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    @Test
    void shouldParseEnisaEuKevFeed(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlEqualTo("/eukev.json")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(/* language=JSON */ """
                        [
                          {
                            "cveID": "CVE-2026-41940",
                            "dateReported": "2026/05/08",
                            "shortDescription": "Auth bypass",
                            "exploitationType": "ransomware"
                          },
                          {
                            "cveID": "CVE-2026-1731",
                            "dateReported": "2026/06/04",
                            "shortDescription": "Pre-auth RCE",
                            "exploitationType": "-"
                          }
                        ]
                        """)));

        final var dataSource = new EnisaKevDataSource(
                HttpClient.newHttpClient(),
                objectMapper,
                URI.create(wmRuntimeInfo.getHttpBaseUrl() + "/eukev.json"));

        assertThat(dataSource).toIterable().satisfiesExactly(
                first -> {
                    assertThat(first.vulnSource()).isEqualTo("NVD");
                    assertThat(first.vulnId()).isEqualTo("CVE-2026-41940");
                    assertThat(first.publishedAt()).isEqualTo(Instant.parse("2026-05-08T00:00:00Z"));
                    assertThat(first.knownRansomware()).isTrue();
                    assertThat(first.description()).isEqualTo("Auth bypass");
                },
                second -> {
                    assertThat(second.vulnId()).isEqualTo("CVE-2026-1731");
                    assertThat(second.knownRansomware()).isNull();
                });
    }

}
