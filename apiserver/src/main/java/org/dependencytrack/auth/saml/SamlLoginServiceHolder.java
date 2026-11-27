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
package org.dependencytrack.auth.saml;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/// Holds the [SamlLoginService] of the application, created from the configuration on first use.
///
/// @since 5.3.0
public final class SamlLoginServiceHolder {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlLoginServiceHolder.class);

    private static @Nullable SamlLoginService instance;
    private static boolean initialized;

    private SamlLoginServiceHolder() {}

    /// @return The service, or empty when SAML is disabled or misconfigured.
    public static synchronized Optional<SamlLoginService> get() {
        if (!initialized) {
            instance = create();
            initialized = true;
        }
        return Optional.ofNullable(instance);
    }

    /// Replaces the service, for tests. `null` disables SAML.
    public static synchronized void set(@Nullable SamlLoginService service) {
        instance = service;
        initialized = true;
    }

    /// Forgets the service, so that the next call to [#get()] reads the configuration again. For tests.
    public static synchronized void reset() {
        instance = null;
        initialized = false;
    }

    private static @Nullable SamlLoginService create() {
        try {
            return SamlConfig.load(ConfigProvider.getConfig())
                    .map(SamlLoginService::new)
                    .orElse(null);
        } catch (IllegalStateException e) {
            LOGGER.error("SAML is enabled, but its configuration is invalid; SAML login is unavailable", e);
            return null;
        }
    }
}
