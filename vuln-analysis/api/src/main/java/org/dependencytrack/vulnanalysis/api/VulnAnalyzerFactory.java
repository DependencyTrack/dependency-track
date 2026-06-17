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
package org.dependencytrack.vulnanalysis.api;

import org.dependencytrack.plugin.api.ExtensionFactory;

import java.util.EnumSet;

/**
 * An {@link ExtensionFactory} for creating {@link VulnAnalyzer} instances.
 *
 * @since 5.0.0
 */
public interface VulnAnalyzerFactory extends ExtensionFactory<VulnAnalyzer> {

    @Override
    default int priority() {
        return 0;
    }

    /**
     * @return Whether the analyzer is enabled.
     */
    boolean isEnabled();

    /**
     * Declares which component data the analyzer needs to perform its analysis.
     * <p>
     * For example, an analyzer that queries the NVD by CPE would return
     * {@link VulnAnalyzerRequirement#COMPONENT_CPE}.
     * <p>
     * Requirements are aggregated across all enabled analyzers. The resulting BOM passed to
     * {@link VulnAnalyzer#analyze(org.cyclonedx.proto.v1_7.Bom)} may thus contain more
     * data than any single analyzer requested. Requirements are satisfied on a best-effort basis,
     * and components provided to analyzers may lack the requested fields.
     * <p>
     * Note that group, name, and version is always provided for all components.
     *
     * @return Requirements for this analyzer.
     */
    EnumSet<VulnAnalyzerRequirement> analyzerRequirements();

}
