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
package org.dependencytrack.plugin.runtime;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class DeploymentConfigImplTest {

    private final Config delegateConfig = new SmallRyeConfigBuilder()
            .withDefaultValue("dt.extension-point-name.extension-name.foo", "bar")
            .build();
    private final DeploymentConfig deploymentConfig =
            new DeploymentConfigImpl(
                    delegateConfig, "extension-point-name", "extension-name");

    @Test
    void shouldThrowWhenDelegateIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new DeploymentConfigImpl(
                        null, "extension-point-name", "extension-name"))
                .withMessage("delegate must not be null");
    }

    @Test
    void shouldResolveGetValueAgainstNamespacedKey() {
        assertThat(deploymentConfig.getValue("foo", String.class)).isEqualTo("bar");
    }

    @Test
    void shouldResolveGetOptionalValueAgainstNamespacedKey() {
        assertThat(deploymentConfig.getOptionalValue("foo", String.class))
                .isEqualTo(Optional.of("bar"));
        assertThat(deploymentConfig.getOptionalValue("missing", String.class))
                .isEmpty();
    }

}
