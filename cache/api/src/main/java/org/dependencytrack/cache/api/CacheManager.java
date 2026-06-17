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
package org.dependencytrack.cache.api;

import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public interface CacheManager extends Closeable {

    Cache getCache(String name);

    Pattern VALID_NAME_PATTERN = Pattern.compile("^[a-z0-9\\-.]{3,128}$");

    static void requireValidName(@Nullable String name) {
        requireNonNull(name, "name must not be null");
        if (!VALID_NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException(
                    "name does not match expected pattern %s: %s".formatted(
                            VALID_NAME_PATTERN.pattern(), name));
        }
    }

}
