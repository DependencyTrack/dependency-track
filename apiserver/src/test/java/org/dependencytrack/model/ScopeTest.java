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
package org.dependencytrack.model;

import io.smallrye.config.EnvConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.dependencytrack.common.ConfigKeys.BOM_DEFAULT_COMPONENT_SCOPE;

class ScopeTest {

    @AfterEach
    void clearDefaultScope() {
        MemoryConfigSource.removeProperty(BOM_DEFAULT_COMPONENT_SCOPE);
    }

    @Test
    void shouldPreserveLegacyBehaviorWhenDefaultIsNotConfigured() {
        assertThat(Scope.getMappedScope(null)).isNull();
    }

    @ParameterizedTest
    @EnumSource(Scope.class)
    void shouldResolveDefaultFromEnvironment(final Scope expected) {
        final var config = new SmallRyeConfigBuilder()
                .withSources(new EnvConfigSource(Map.of("DT_BOM_DEFAULT_COMPONENT_SCOPE", expected.name()), 300))
                .build();

        assertThat(Scope.getDefaultScope(config)).contains(expected);
    }

    @Test
    void shouldRejectInvalidConfiguredDefault() {
        final var config = new SmallRyeConfigBuilder()
                .withSources(new EnvConfigSource(Map.of("DT_BOM_DEFAULT_COMPONENT_SCOPE", "INVALID"), 300))
                .build();

        assertThatIllegalArgumentException().isThrownBy(() -> Scope.getDefaultScope(config));
    }

    @ParameterizedTest
    @EnumSource(Scope.class)
    void shouldMapMissingScopeAndPreserveExplicitScopes(final Scope defaultScope) {
        MemoryConfigSource.setProperty(BOM_DEFAULT_COMPONENT_SCOPE, defaultScope.name());
        assertThat(Scope.getMappedScope(null)).isEqualTo(defaultScope);

        for (final var explicitScope : org.cyclonedx.model.Component.Scope.values()) {
            assertThat(Scope.getMappedScope(explicitScope)).isEqualTo(Scope.valueOf(explicitScope.name()));
        }
    }

    @Test
    void shouldMapBothComponentIdentityAndModelConsistently() {
        MemoryConfigSource.setProperty(BOM_DEFAULT_COMPONENT_SCOPE, "REQUIRED");

        final var component = new org.cyclonedx.model.Component();
        component.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");

        final var omittedIdentity = new ComponentIdentity(component);
        final var converted = ModelConverter.convertComponent(component);
        assertThat(converted.getScope()).isEqualTo(Scope.REQUIRED);

        component.setScope(org.cyclonedx.model.Component.Scope.REQUIRED);
        final var explicitIdentity = new ComponentIdentity(component);
        assertThat(omittedIdentity).isEqualTo(explicitIdentity);
        assertThat(omittedIdentity.hashCode()).isEqualTo(explicitIdentity.hashCode());
        assertThat(new ComponentIdentity(converted, true)).isEqualTo(explicitIdentity);

        component.setScope(org.cyclonedx.model.Component.Scope.OPTIONAL);
        assertThat(new ComponentIdentity(component)).isNotEqualTo(omittedIdentity);
    }
}
