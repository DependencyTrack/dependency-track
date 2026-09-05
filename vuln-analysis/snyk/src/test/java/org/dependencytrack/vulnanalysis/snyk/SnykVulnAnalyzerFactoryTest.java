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
package org.dependencytrack.vulnanalysis.snyk;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SnykVulnAnalyzerFactoryTest extends AbstractExtensionFactoryTest<VulnAnalyzer, SnykVulnAnalyzerFactory> {

    SnykVulnAnalyzerFactoryTest() {
        super(SnykVulnAnalyzerFactory.class);
    }

    @Test
    void shouldEnableBatchRequestsWhenNotConfigured() throws Exception {
        // Configs stored before this option existed do not have the field, and must keep
        // using the batch endpoint rather than silently switching to per-package requests.
        final var config = new ObjectMapper().readValue("""
                        {"enabled":true,"apiBaseUrl":"https://api.snyk.io","orgId":"org","apiToken":"token"}
                        """, SnykVulnAnalyzerConfigV1.class);

        assertThat(config.isBatchRequestsEnabled()).isTrue();
    }
}
