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
package org.dependencytrack.secret.management.database;

import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.nio.file.Path;
import java.util.Base64;

/**
 * @since 5.0.0
 */
final class DatabaseSecretManagerConfig {

    private static final String PREFIX = "dt.secret-management.database.";

    private final Config config;

    DatabaseSecretManagerConfig(final Config config) {
        this.config = config;
    }

    String getDataSourceName() {
        return config.getValue(PREFIX + "datasource.name", String.class);
    }

    byte @Nullable [] getKek() {
        final String propertyName = PREFIX + "kek";

        final String encodedKek = config
                .getOptionalValue(propertyName, String.class)
                .orElse(null);
        if (encodedKek == null) {
            return null;
        }

        final byte[] kekBytes;
        try {
            kekBytes = Base64.getDecoder().decode(encodedKek);
        } catch (IllegalArgumentException e) {
            // NB: Original exception is intentionally not logged to avoid leaking the key.
            throw new IllegalStateException(
                    "The provided %s value is not base64 encoded".formatted(propertyName));
        }

        if (kekBytes.length != 32) {
            throw new IllegalStateException(
                    "KEK provided via %s must be 32 bytes, but is %d".formatted(
                            propertyName, kekBytes.length));
        }

        return kekBytes;
    }

    Path getKekKeysetPath() {
        return config.getValue(PREFIX + "kek-keyset.path", Path.class);
    }

    boolean isCreateKekKeysetIfMissing() {
        return config.getValue(PREFIX + "kek-keyset.create-if-missing", boolean.class);
    }

}
