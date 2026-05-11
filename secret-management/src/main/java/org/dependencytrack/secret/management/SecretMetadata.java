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

import org.jspecify.annotations.Nullable;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Metadata of a secret.
 * <p>
 * Note that the availability of fields depends on the {@link SecretManager} implementation.
 *
 * @since 5.0.0
 */
public record SecretMetadata(
        String name,
        @Nullable String description,
        @Nullable Instant createdAt,
        @Nullable Instant updatedAt) {

    public SecretMetadata {
        requireNonNull(name, "name must not be null");
    }

}
