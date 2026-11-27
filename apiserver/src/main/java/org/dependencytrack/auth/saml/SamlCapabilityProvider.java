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

import org.dependencytrack.capabilities.CapabilityProvider;

import java.util.Map;
import java.util.function.BooleanSupplier;

/// Tells clients before login whether they can offer login via SAML.
///
/// SAML is disabled by default. As for OIDC, the namespace always reports `disabled` explicitly,
/// because an absent namespace would mean that the feature is enabled.
///
/// @since 5.3.0
public final class SamlCapabilityProvider implements CapabilityProvider {

    private final BooleanSupplier availability;

    @SuppressWarnings("unused") // Used by ServiceLoader.
    public SamlCapabilityProvider() {
        this(() -> SamlLoginServiceHolder.get().isPresent());
    }

    SamlCapabilityProvider(BooleanSupplier availability) {
        this.availability = availability;
    }

    @Override
    public String namespace() {
        return "saml";
    }

    @Override
    public boolean isPublic() {
        return true;
    }

    @Override
    public Map<String, Object> capabilities() {
        return Map.of("disabled", !availability.getAsBoolean());
    }
}
