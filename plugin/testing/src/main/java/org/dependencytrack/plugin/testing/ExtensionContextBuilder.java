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
package org.dependencytrack.plugin.testing;

import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jspecify.annotations.Nullable;

import java.net.http.HttpClient;
import java.util.Map;

/// Builds [ExtensionContext]s for tests, defaulting any service not explicitly provided.
///
/// @since 5.2.0
public final class ExtensionContextBuilder {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CacheManager cacheManager;
    private @Nullable KeyValueStore keyValueStore;
    private @Nullable HttpClient httpClient;

    public ExtensionContextBuilder withConfigRegistry(ConfigRegistry configRegistry) {
        this.configRegistry = configRegistry;
        return this;
    }

    public ExtensionContextBuilder withCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        return this;
    }

    public ExtensionContextBuilder withKeyValueStore(KeyValueStore keyValueStore) {
        this.keyValueStore = keyValueStore;
        return this;
    }

    public ExtensionContextBuilder withHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
        return this;
    }

    public ExtensionContext build() {
        return new ExtensionContext(
                configRegistry != null ? configRegistry : new MockConfigRegistry(Map.of()),
                cacheManager != null ? cacheManager : new NoopCacheManager(),
                keyValueStore != null ? keyValueStore : new MockKeyValueStore(),
                httpClient != null ? httpClient : HttpClient.newHttpClient());
    }
}
