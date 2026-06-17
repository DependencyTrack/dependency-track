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
import org.dependencytrack.e2e.api.model.EventProcessingResponse;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.Finding;
import org.dependencytrack.e2e.api.model.Project;
import org.dependencytrack.e2e.api.model.UpdateExtensionConfigRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class BomUploadOssIndexAnalysisE2ET extends AbstractE2ET {

    private String ossIndexUsername;
    private String ossIndexApiToken;

    @Override
    @BeforeEach
    void beforeEach() throws Exception {
        ossIndexUsername = System.getenv("OSSINDEX_USERNAME");
        ossIndexApiToken = System.getenv("OSSINDEX_TOKEN");

        // OSS Index does not allow unauthenticated usage; No point in running the test without credentials.
        assumeTrue(ossIndexUsername != null, "No OSS Index username provided");
        assumeTrue(ossIndexApiToken != null, "No OSS Index API token provided");

        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(GenericContainer<?> container) {
        container
                .withEnv("DT_SECRET_MANAGEMENT_PROVIDER", "env")
                .withEnv("DT_SECRET_OSSINDEX_API_TOKEN", ossIndexApiToken);
    }

    @Test
    void test() throws Exception {
        logger.info("Disabling internal vuln analyzer");
        apiClient.updateExtensionConfig(
                "vuln-analyzer",
                "internal",
                new UpdateExtensionConfigRequest(Map.of("enabled", false)));

        logger.info("Configuring OSS Index vuln analyzer");
        apiClient.updateExtensionConfig(
                "vuln-analyzer",
                "oss-index",
                new UpdateExtensionConfigRequest(
                        Map.ofEntries(
                                Map.entry("enabled", true),
                                Map.entry("apiUrl", "https://ossindex.sonatype.org"),
                                Map.entry("username", ossIndexUsername),
                                Map.entry("apiToken", "OSSINDEX_API_TOKEN"))));

        // Parse and base64 encode a BOM.
        final byte[] bomBytes = getClass().getResourceAsStream("/dtrack-apiserver-4.5.0.bom.json").readAllBytes();
        final String bomBase64 = Base64.getEncoder().encodeToString(bomBytes);

        // Upload the BOM
        final EventTokenResponse response = apiClient.uploadBom(new BomUploadRequest("foo", "bar", true, bomBase64));
        assertThat(response.token()).isNotEmpty();

        // Wait up to 15sec for the BOM processing to complete.
        await("BOM processing")
                .atMost(Duration.ofSeconds(30))
                .pollDelay(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    final EventProcessingResponse processingResponse = apiClient.isEventBeingProcessed(response.token());
                    assertThat(processingResponse.processing()).isFalse();
                });

        // Lookup the project we just created.
        final Project project = apiClient.lookupProject("foo", "bar");

        // Ensure that vulnerabilities have been reported correctly.
        final List<Finding> findings = apiClient.getFindings(project.uuid(), false);
        assertThat(findings)
                .hasSizeGreaterThan(1)
                .allSatisfy(
                        finding -> {
                            assertThat(finding.vulnerability()).satisfiesAnyOf(
                                    vuln -> {
                                        assertThat(vuln.vulnId()).startsWith("CVE-");
                                        assertThat(vuln.source()).isEqualTo("NVD");
                                    },
                                    vuln -> {
                                        assertThat(vuln.vulnId()).startsWith("sonatype-");
                                        assertThat(vuln.source()).isEqualTo("OSSINDEX");
                                    }
                            );
                            assertThat(finding.attribution().analyzerIdentity()).isEqualTo("oss-index");
                            assertThat(finding.attribution().attributedOn()).isNotBlank();
                        }
                );
    }

}
