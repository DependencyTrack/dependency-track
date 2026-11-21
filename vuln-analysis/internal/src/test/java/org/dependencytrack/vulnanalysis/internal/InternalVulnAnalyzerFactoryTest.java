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
package org.dependencytrack.vulnanalysis.internal;

import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InternalVulnAnalyzerFactoryTest extends AbstractExtensionFactoryTest<VulnAnalyzer, InternalVulnAnalyzerFactory> {

    protected InternalVulnAnalyzerFactoryTest() {
        super(InternalVulnAnalyzerFactory.class);
    }

    @Test
    void shouldRequireComponentProperties() {
        // Without this requirement the apiserver omits component properties,
        // and the trivy `SrcName` fallback for source package matching gets no data.
        assertThat(factory.analyzerRequirements()).contains(VulnAnalyzerRequirement.COMPONENT_PROPERTIES);
    }
}
