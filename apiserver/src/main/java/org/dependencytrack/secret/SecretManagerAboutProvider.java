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

import alpine.common.AboutProvider;
import org.dependencytrack.secret.management.SecretManager;
import org.jspecify.annotations.Nullable;

import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

/**
 * @since 5.0.0
 */
public final class SecretManagerAboutProvider implements AboutProvider {

    private final Supplier<SecretManager> instanceSupplier;

    SecretManagerAboutProvider(final Supplier<@Nullable SecretManager> instanceSupplier) {
        this.instanceSupplier = instanceSupplier;
    }

    @SuppressWarnings("unused")
    public SecretManagerAboutProvider() {
        // TODO: Find a way to get rid of this, we shouldn't rely on singletons.
        this(() -> SecretManagerInitializer.secretManager);
    }

    @Override
    public String name() {
        return "secretManager";
    }

    @Override
    public Map<String, Object> collect() {
        SecretManager secretManager = instanceSupplier.get();
        if (secretManager == null) {
            return Collections.emptyMap();
        }

        return Map.ofEntries(
                Map.entry("provider", secretManager.name()),
                Map.entry("readOnly", secretManager.isReadOnly()));
    }

}
