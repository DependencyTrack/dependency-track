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
package org.dependencytrack.plugin.runtime;

import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.List;
import java.util.SequencedCollection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class PluginManagerTest extends AbstractDatabaseTest {

    interface UnknownExtensionPoint extends ExtensionPoint {
    }

    private PluginManager pluginManager;

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                ConfigProvider.getConfig(),
                new NoopCacheManager(),
                secretName -> null,
                jdbi,
                HttpClient.newHttpClient(),
                List.of(TestExtensionPoint.class));
        pluginManager.loadPlugins(List.of(new DummyPlugin()));
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void testGetLoadedPlugins() {
        final SequencedCollection<Plugin> loadedPlugins =
                pluginManager.getLoadedPlugins();
        assertThat(loadedPlugins).isNotEmpty();
        assertThat(loadedPlugins).isUnmodifiable();
    }

    @Test
    void testGetExtensionByName() {
        final TestExtensionPoint extension =
                pluginManager.getExtension(TestExtensionPoint.class, "dummy");
        assertThat(extension).isNotNull();
    }

    @Test
    void testGetExtensionByNameWhenNoExists() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> pluginManager.getExtension(TestExtensionPoint.class, "doesNotExist"))
                .withMessage("No extension named 'doesNotExist' exists for the extension point 'test'");
    }

    @Test
    void testGetFactories() {
        final SequencedCollection<ExtensionFactory<TestExtensionPoint>> factories =
                pluginManager.getFactories(TestExtensionPoint.class);
        assertThat(factories).satisfiesExactly(factory ->
                assertThat(factory).isExactlyInstanceOf(DummyTestExtensionFactory.class));
    }

    @Test
    void testGetFactoriesForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> pluginManager.getFactories(UnknownExtensionPoint.class));
    }

    @Test
    void testGetKVStore() {
        final KeyValueStore kvStore =
                pluginManager.getKVStore(TestExtensionPoint.class, "dummy");
        assertThat(kvStore).isInstanceOf(KeyValueStoreImpl.class);
    }

    @Test
    void testGetKVStoreForUnknownExtensionPoint() {
        assertThatExceptionOfType(NoSuchExtensionPointException.class)
                .isThrownBy(() -> pluginManager.getKVStore(UnknownExtensionPoint.class, "dummy"));
    }

    @Test
    void testGetKVStoreForUnknownExtension() {
        assertThatExceptionOfType(NoSuchExtensionException.class)
                .isThrownBy(() -> pluginManager.getKVStore(TestExtensionPoint.class, "doesNotExist"));
    }

    @Test
    void testLoadPluginsRepeatedly() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> pluginManager.loadPlugins(List.of(new DummyPlugin())))
                .withMessage("Plugins were already loaded; Unload them first");
    }

}
