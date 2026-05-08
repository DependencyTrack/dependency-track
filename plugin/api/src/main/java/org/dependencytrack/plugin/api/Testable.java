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
package org.dependencytrack.plugin.api;

import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.jspecify.annotations.Nullable;

/**
 * Capability interface for {@link ExtensionFactory} implementations
 * that support testing whether the extension is operational.
 *
 * @since 5.0.0
 */
public interface Testable {

    /**
     * Performs a test whether the extension is operational with the provided runtime config.
     *
     * @param runtimeConfig The runtime config to test with. {@code null} when the extension
     *                      does not support runtime configuration.
     * @return The test result.
     */
    ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig);

}
