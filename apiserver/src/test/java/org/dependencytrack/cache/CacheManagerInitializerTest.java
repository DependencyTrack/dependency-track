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
package org.dependencytrack.cache;

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.CacheManager;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CacheManagerInitializerTest extends PersistenceCapableTest {

    @Test
    void shouldInitializeCacheProvider() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.cache.provider", "database"),
                        Map.entry("dt.cache.provider.database.datasource.name", "default")))
                .build();

        final var initializer = new CacheManagerInitializer(config);

        final var servletContextMock = mock(ServletContext.class);

        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(servletContextMock).setAttribute(eq(CacheManager.class.getName()), any(CacheManager.class));

        initializer.contextDestroyed(new ServletContextEvent(servletContextMock));
    }

    @Test
    void shouldThrowWhenNoCacheProviderConfigured() {
        final var config = new SmallRyeConfigBuilder().build();

        final var initializer = new CacheManagerInitializer(config);

        assertThatExceptionOfType(NoSuchElementException.class)
                .isThrownBy(() -> initializer.contextInitialized(null))
                .withMessageContaining("config property dt.cache.provider is required");
    }

    @Test
    void shouldThrowWhenConfiguredCacheProviderDoesNotExist() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.cache.provider", "does-not-exist")
                .build();

        final var initializer = new CacheManagerInitializer(config);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> initializer.contextInitialized(null))
                .withMessage("No cache provider found for name: does-not-exist");
    }

}