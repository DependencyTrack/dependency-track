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
package org.dependencytrack.vulnanalysis.trivy;

import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThatNoException;

class TrivyVulnAnalyzerFactoryTest extends AbstractExtensionFactoryTest<VulnAnalyzer, TrivyVulnAnalyzerFactory> {

    TrivyVulnAnalyzerFactoryTest() {
        super(TrivyVulnAnalyzerFactory.class);
    }

    @Test
    void shouldAcceptConfigWithoutApiToken() {
        // Trivy servers do not require a token unless one was configured with --token,
        // so a deployment can legitimately have no token to provide.
        final var config = new TrivyVulnAnalyzerConfigV1()
                .withEnabled(true)
                .withApiUrl(URI.create("http://localhost:8080"))
                .withIgnoreUnfixed(false)
                .withScanLibrary(true)
                .withScanOs(false);

        assertThatNoException()
                .isThrownBy(() -> RuntimeConfigMapper.getInstance()
                        .validate(config, ((RuntimeConfigurable) factory).runtimeConfigSpec()));
    }
}
