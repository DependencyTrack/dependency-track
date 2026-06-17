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
package org.dependencytrack.secret;

import org.dependencytrack.capabilities.CapabilityProvider;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.hk2.api.ServiceLocator;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class SecretManagementCapabilityProvider implements CapabilityProvider {

    private @Nullable Supplier<SecretManager> secretManagerSupplier;

    @SuppressWarnings("unused") // Used by ServiceLoader.
    public SecretManagementCapabilityProvider() {
    }

    @Override
    public String namespace() {
        return "secret_management";
    }

    @Override
    public void init(ServiceLocator serviceLocator) {
        this.secretManagerSupplier = () -> serviceLocator.getService(SecretManager.class);
    }

    @Override
    public Map<String, Object> capabilities() {
        if (secretManagerSupplier == null) {
            return Map.of();
        }

        final SecretManager secretManager = requireNonNull(
                secretManagerSupplier.get(),
                "secretManager must not be null");
        return Map.of("read_only", secretManager.isReadOnly());
    }

}
