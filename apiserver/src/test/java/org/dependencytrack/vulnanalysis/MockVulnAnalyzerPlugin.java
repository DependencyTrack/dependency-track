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
package org.dependencytrack.vulnanalysis;

import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.jspecify.annotations.NonNull;

import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.function.Function;

public final class MockVulnAnalyzerPlugin implements Plugin {

    private final MockVulnAnalyzerFactory factory;

    public MockVulnAnalyzerPlugin(Function<Bom, Bom> analyzeFn) {
        this.factory = new MockVulnAnalyzerFactory(analyzeFn, EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL));
    }

    public MockVulnAnalyzerPlugin(Function<Bom, Bom> analyzeFn, EnumSet<VulnAnalyzerRequirement> requirements) {
        this.factory = new MockVulnAnalyzerFactory(analyzeFn, requirements);
    }

    @Override
    public @NonNull Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(factory);
    }

    private static final class MockVulnAnalyzer implements VulnAnalyzer {

        private final Function<Bom, Bom> analyzeFn;

        MockVulnAnalyzer(Function<Bom, Bom> analyzeFn) {
            this.analyzeFn = analyzeFn;
        }

        @Override
        public Bom analyze(Bom bom) {
            return analyzeFn.apply(bom);
        }
    }

    private static final class MockVulnAnalyzerFactory implements VulnAnalyzerFactory {

        private final Function<Bom, Bom> analyzeFn;
        private final EnumSet<VulnAnalyzerRequirement> requirements;

        MockVulnAnalyzerFactory(Function<Bom, Bom> analyzeFn, EnumSet<VulnAnalyzerRequirement> requirements) {
            this.analyzeFn = analyzeFn;
            this.requirements = requirements;
        }

        @Override
        public @NonNull String extensionName() {
            return "mock";
        }

        @Override
        public @NonNull Class<? extends VulnAnalyzer> extensionClass() {
            return MockVulnAnalyzer.class;
        }

        @Override
        public void init(@NonNull ServiceRegistry serviceRegistry) {
        }

        @Override
        public VulnAnalyzer create() {
            return new MockVulnAnalyzer(analyzeFn);
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public @NonNull EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
            return requirements;
        }
    }

}
