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

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.jspecify.annotations.Nullable;

import java.util.Map;

public final class TestSecretManager implements SecretManager {

    public static final String NAME = "test";

    private final Map<String, String> secretByName;

    public TestSecretManager() {
        this.secretByName = Map.of();
    }

    public TestSecretManager(Map<String, String> secretByName) {
        this.secretByName = Map.copyOf(secretByName);
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean isReadOnly() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void createSecret(
            String name,
            @Nullable String description,
            String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean updateSecret(
            String name,
            @Nullable String description,
            String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteSecret(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @Nullable String getSecretValue(String name) {
        if (!secretByName.isEmpty()) {
            return secretByName.get(name);
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public @Nullable SecretMetadata getSecretMetadata(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Page<SecretMetadata> listSecretMetadata(ListSecretsRequest request) {
        throw new UnsupportedOperationException();
    }

}