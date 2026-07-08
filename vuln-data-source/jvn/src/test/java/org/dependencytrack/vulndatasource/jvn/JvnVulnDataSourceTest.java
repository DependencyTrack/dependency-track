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
package org.dependencytrack.vulndatasource.jvn;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WireMockTest
class JvnVulnDataSourceTest {

    private static final int YEAR = 2026;
    private static final String FEED_FILENAME = "jvndb_detail_" + YEAR + ".rdf";

    @Test
    void iteratesYearlyFeedToBov(final WireMockRuntimeInfo wm) throws Exception {
        final String detailXml = new String(
                getClass().getResourceAsStream("/jvn-detail-with-range.xml").readAllBytes(),
                StandardCharsets.UTF_8);
        final String checksumJson = """
                [{"url":"x","filename":"%s","sha256":"deadbeef","size":1,"lastModified":"2026/01/01 00:00:00"}]
                """.formatted(FEED_FILENAME);

        stubFor(get(urlPathEqualTo("/checksum.txt"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(checksumJson)));
        stubFor(get(urlPathEqualTo("/detail/" + FEED_FILENAME))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(detailXml)));

        final var client = new JvnClient(HttpClient.newHttpClient(), wm.getHttpBaseUrl());
        final var watermark = new WatermarkManager(new MockKeyValueStore(), List.of(FEED_FILENAME));

        final var boms = new ArrayList<Bom>();
        try (final var dataSource = new JvnVulnDataSource(client, watermark, YEAR, YEAR)) {
            while (dataSource.hasNext()) {
                final Bom bom = dataSource.next();
                dataSource.markProcessed(bom);
                boms.add(bom);
            }
        }

        assertEquals(1, boms.size());
        final Bom bom = boms.getFirst();
        assertEquals(1, bom.getComponentsCount());
        assertEquals("cpe:2.3:a:suse:rancher_fleet:*:*:*:*:*:*:*:*", bom.getComponents(0).getCpe());
        assertEquals(1, bom.getVulnerabilitiesCount());
        // Every JVN advisory is stored as-is under the JVN source, keyed by its JVNDB id
        // (no CVE->NVD routing), even when it carries a CVE.
        assertEquals("JVN", bom.getVulnerabilities(0).getSource().getName());
        assertTrue(bom.getVulnerabilities(0).getId().startsWith("JVNDB-"));
        assertEquals(4, bom.getVulnerabilities(0).getAffects(0).getVersionsCount());
    }
}
