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
package org.dependencytrack.plugin.api;

import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;

import java.net.http.HttpClient;

import static java.util.Objects.requireNonNull;

/// Platform services provided by the host application to an extension.
///
/// Extensions that are unable to use [HttpClient] but still require proxy configuration
/// can acquire a [java.net.ProxySelector] through [HttpClient#proxy()].
///
/// @param configRegistry Access to deployment and runtime configuration of the extension.
/// @param cacheManager   Access to caches, namespaced to the extension.
/// @param keyValueStore  Access to persistent key-value storage, namespaced to the extension.
/// @param httpClient     HTTP client configured according to the host application's settings.
/// @since 5.2.0
public record ExtensionContext(
        ConfigRegistry configRegistry, CacheManager cacheManager, KeyValueStore keyValueStore, HttpClient httpClient) {

    public ExtensionContext {
        requireNonNull(configRegistry, "configRegistry must not be null");
        requireNonNull(cacheManager, "cacheManager must not be null");
        requireNonNull(keyValueStore, "keyValueStore must not be null");
        requireNonNull(httpClient, "httpClient must not be null");
    }
}
