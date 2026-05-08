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

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class NamespacedCacheManager implements CacheManager {

    private final CacheManager delegate;
    private final String namespace;

    public NamespacedCacheManager(CacheManager delegate, String namespace) {
        this.delegate = requireNonNull(delegate, "delegate must not be null");
        this.namespace = requireNonNull(namespace, "namespace must not be null");
        if (!VALID_NAME_PATTERN.matcher(namespace).matches()) {
            throw new IllegalArgumentException(
                    "namespace does not match expected pattern %s: %s".formatted(
                            VALID_NAME_PATTERN.pattern(), namespace));
        }
    }

    @Override
    public Cache getCache(String name) {
        return delegate.getCache("%s.%s".formatted(namespace, name));
    }

    @Override
    public void close() {
    }

}
