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
package org.dependencytrack.secret.management;

import org.dependencytrack.common.pagination.Page;
import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public interface SecretManager extends Closeable {

    /**
     * @return Name of the manager. Should be identical to the corresponding {@link SecretManagerProvider#name()}.
     */
    String name();

    /**
     * @return Whether the secret manager is read-only.
     */
    boolean isReadOnly();

    /**
     * Create a new secret.
     *
     * @param name        Name of the secret.
     * @param description Description of the secret.
     * @param value       The secret value.
     * @throws UnsupportedOperationException When creation of secrets is not supported.
     * @throws SecretAlreadyExistsException  When a secret with the given name already exists.
     */
    void createSecret(String name, @Nullable String description, String value);

    /**
     * Update an existing secret.
     *
     * @param name        Name of the secret.
     * @param description Description of the secret.
     * @param value       The secret value.
     * @return Whether the secret was updated. Implementations may choose to
     * not perform an update operation when all updatable fields are specified as {@code null}.
     * When {@code false} is returned, the secret can be assumed to be unchanged.
     * @throws UnsupportedOperationException When updating of secrets is not supported.
     * @throws NoSuchElementException        When a secret with the given name does not exist.
     */
    boolean updateSecret(String name, @Nullable String description, @Nullable String value);

    /**
     * Delete a secret.
     *
     * @param name Name of the secret.
     * @throws UnsupportedOperationException When deletion of secrets is not supported.
     * @throws NoSuchElementException        When a secret with the given name does not exist.
     */
    void deleteSecret(String name);

    /**
     * @param name Name of the secret.
     * @return The plain text value of the secret.
     */
    @Nullable String getSecretValue(String name);

    /**
     * @param name Name of the secret.
     * @return Secret metadata.
     */
    @Nullable SecretMetadata getSecretMetadata(String name);

    /**
     * @return A list of metadata about all secrets.
     */
    Page<SecretMetadata> listSecretMetadata(ListSecretsRequest request);

    @Override
    default void close() {
    }

    Pattern VALID_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    static void requireValidName(final String name) {
        requireNonNull(name, "name must not be null");
        if (!VALID_NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException(
                    "name does not match expected pattern %s: %s".formatted(
                            VALID_NAME_PATTERN.pattern(), name));
        }
    }

}
