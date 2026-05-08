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

import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NamespacedCacheManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.eclipse.microprofile.config.Config;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Closeable;
import java.lang.reflect.Modifier;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.SequencedMap;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_HIGHEST;
import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_LOWEST;
import static org.dependencytrack.plugin.runtime.MdcKeys.MDC_EXTENSION;
import static org.dependencytrack.plugin.runtime.MdcKeys.MDC_EXTENSION_NAME;
import static org.dependencytrack.plugin.runtime.MdcKeys.MDC_EXTENSION_POINT;
import static org.dependencytrack.plugin.runtime.MdcKeys.MDC_EXTENSION_POINT_NAME;
import static org.dependencytrack.plugin.runtime.MdcKeys.MDC_PLUGIN;

/**
 * @since 5.0.0
 */
public class PluginManager implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(PluginManager.class);
    private static final Pattern EXTENSION_POINT_NAME_PATTERN = Pattern.compile("^[a-z0-9\\-]+$");
    private static final Pattern EXTENSION_NAME_PATTERN = EXTENSION_POINT_NAME_PATTERN;

    private final Config config;
    private final CacheManager cacheManager;
    private final RuntimeConfigMapper runtimeConfigMapper;
    private final Function<String, @Nullable String> secretResolver;
    private final Jdbi jdbi;
    private final HttpClient httpClient;
    private final SequencedMap<Class<? extends Plugin>, Plugin> loadedPluginByClass;
    private final Map<ExtensionIdentity, Plugin> pluginByExtensionIdentity;
    private final Map<Plugin, List<ExtensionFactory<?>>> factoriesByPlugin;
    private final Map<Class<? extends ExtensionPoint>, ExtensionPointMetadata> metadataByExtensionPointClass;
    private final Map<Class<? extends ExtensionPoint>, Set<String>> extensionNamesByExtensionPointClass;
    private final Map<ExtensionIdentity, ExtensionFactory<?>> factoryByExtensionIdentity;
    private final Map<ExtensionIdentity, ConfigRegistry> configRegistryByExtensionIdentity;
    private final Map<Class<? extends ExtensionPoint>, ExtensionFactory<?>> defaultFactoryByExtensionPointClass;
    private final Comparator<ExtensionFactory<?>> factoryComparator;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final ReentrantLock lock;

    public PluginManager(
            Config config,
            CacheManager cacheManager,
            Function<String, @Nullable String> secretResolver,
            Jdbi jdbi,
            HttpClient httpClient,
            Collection<Class<? extends ExtensionPoint>> extensionPointClasses) {
        this.config = config;
        this.cacheManager = cacheManager;
        this.secretResolver = secretResolver;
        this.jdbi = jdbi;
        this.httpClient = httpClient;
        this.runtimeConfigMapper = RuntimeConfigMapper.getInstance();
        this.loadedPluginByClass = new LinkedHashMap<>();
        this.pluginByExtensionIdentity = new HashMap<>();
        this.factoriesByPlugin = new HashMap<>();
        this.metadataByExtensionPointClass = new HashMap<>();
        this.extensionNamesByExtensionPointClass = new HashMap<>();
        this.factoryByExtensionIdentity = new HashMap<>();
        this.configRegistryByExtensionIdentity = new HashMap<>();
        this.defaultFactoryByExtensionPointClass = new HashMap<>();
        this.factoryComparator = Comparator
                .<ExtensionFactory<?>>comparingInt(ExtensionFactory::priority)
                .thenComparing(ExtensionFactory::extensionName);
        this.lock = new ReentrantLock();

        registerExtensionPoints(extensionPointClasses);
    }

    private void registerExtensionPoints(Collection<Class<? extends ExtensionPoint>> extensionPointClasses) {
        for (final var extensionPointClass : extensionPointClasses) {
            final var specAnnotation = extensionPointClass.getAnnotation(ExtensionPointSpec.class);
            if (specAnnotation == null) {
                throw new IllegalArgumentException(
                        "Extension point %s is not annotated with %s".formatted(
                                extensionPointClass.getName(), ExtensionPointSpec.class.getName()));
            }

            if (!EXTENSION_POINT_NAME_PATTERN.matcher(specAnnotation.name()).matches()) {
                throw new IllegalStateException(
                        "%s is not a valid extension point name".formatted(specAnnotation.name()));
            }

            LOGGER.debug("Registered extension point %s".formatted(specAnnotation.name()));
            metadataByExtensionPointClass.put(
                    extensionPointClass,
                    new ExtensionPointMetadata(
                            specAnnotation.name(),
                            extensionPointClass,
                            specAnnotation.required()));
        }
    }

    public SequencedCollection<ExtensionPointMetadata> getExtensionPoints() {
        return List.copyOf(metadataByExtensionPointClass.values());
    }

    public SequencedCollection<Plugin> getLoadedPlugins() {
        return List.copyOf(loadedPluginByClass.sequencedValues());
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint> T getExtension(Class<T> extensionPointClass) {
        final ExtensionPointMetadata extensionPointMetadata = requireKnownExtensionPoint(extensionPointClass);

        final ExtensionFactory<?> factory = defaultFactoryByExtensionPointClass.get(extensionPointClass);
        if (factory == null) {
            throw new NoSuchExtensionException(extensionPointMetadata.name());
        }

        return (T) requireNonNull(factory.create(), "extension must not be null");
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint> T getExtension(Class<T> extensionPointClass, String name) {
        final ExtensionPointMetadata extensionPointMetadata = requireKnownExtensionPoint(extensionPointClass);

        final var extensionIdentity = new ExtensionIdentity(extensionPointClass, name);
        final ExtensionFactory<?> factory = factoryByExtensionIdentity.get(extensionIdentity);
        if (factory == null) {
            throw new NoSuchExtensionException(extensionPointMetadata.name(), name);
        }

        return (T) requireNonNull(factory.create(), "extension must not be null");
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> U getFactory(Class<T> extensionPointClass) {
        final ExtensionPointMetadata extensionPointMetadata = requireKnownExtensionPoint(extensionPointClass);

        final ExtensionFactory<?> factory = defaultFactoryByExtensionPointClass.get(extensionPointClass);
        if (factory == null) {
            throw new NoSuchExtensionException(extensionPointMetadata.name());
        }

        return (U) factory;
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> U getFactory(Class<T> extensionPointClass, String name) {
        final ExtensionPointMetadata extensionPointMetadata = requireKnownExtensionPoint(extensionPointClass);

        final var extensionIdentity = new ExtensionIdentity(extensionPointClass, name);
        final ExtensionFactory<?> factory = factoryByExtensionIdentity.get(extensionIdentity);
        if (factory == null) {
            throw new NoSuchExtensionException(extensionPointMetadata.name(), name);
        }

        return (U) factory;
    }

    @SuppressWarnings("unchecked")
    public <T extends ExtensionPoint, U extends ExtensionFactory<T>> SequencedCollection<U> getFactories(Class<T> extensionPointClass) {
        requireKnownExtensionPoint(extensionPointClass);

        final Set<String> extensionNames = extensionNamesByExtensionPointClass.get(extensionPointClass);
        if (extensionNames == null) {
            return Collections.emptyList();
        }

        final var factories = new TreeSet<U>(factoryComparator);
        for (final String extensionName : extensionNames) {
            final var extensionIdentity = new ExtensionIdentity(extensionPointClass, extensionName);
            final ExtensionFactory<?> factory = factoryByExtensionIdentity.get(extensionIdentity);
            if (factory != null) {
                factories.add((U) factory);
            }
        }

        return factories;
    }

    public <T extends ExtensionPoint> ConfigRegistry getConfigRegistry(
            Class<T> extensionPointClass,
            String extensionName) {
        final ExtensionPointMetadata extensionPointMetadata = requireKnownExtensionPoint(extensionPointClass);

        final var extensionIdentity = new ExtensionIdentity(extensionPointClass, extensionName);

        final ConfigRegistry configRegistry =
                configRegistryByExtensionIdentity.get(extensionIdentity);
        if (configRegistry == null) {
            throw new NoSuchExtensionException(extensionPointMetadata.name(), extensionName);
        }

        return configRegistry;
    }

    public <T extends ExtensionPoint> MutableConfigRegistry getMutableConfigRegistry(
            Class<T> extensionPointClass,
            String extensionName) {
        final ConfigRegistry configRegistry = getConfigRegistry(extensionPointClass, extensionName);
        if (configRegistry instanceof final MutableConfigRegistry mutableConfigRegistry) {
            return mutableConfigRegistry;
        }

        throw new IllegalStateException("Config registry is immutable");
    }

    public <T extends ExtensionPoint> KeyValueStore getKVStore(
            Class<T> extensionPointClass,
            String extensionName) {
        final ExtensionPointMetadata extensionPointMetadata = requireKnownExtensionPoint(extensionPointClass);

        final var extensionIdentity = new ExtensionIdentity(extensionPointClass, extensionName);
        if (!factoryByExtensionIdentity.containsKey(extensionIdentity)) {
            throw new NoSuchExtensionException(extensionPointMetadata.name(), extensionName);
        }

        return new KeyValueStoreImpl(jdbi, extensionPointMetadata.name(), extensionName);
    }

    public void loadPlugins(Collection<Plugin> plugins) {
        lock.lock();
        try {
            if (!loadedPluginByClass.isEmpty()) {
                throw new IllegalStateException("Plugins were already loaded; Unload them first");
            }

            loadPluginsLocked(plugins);
        } finally {
            lock.unlock();
        }
    }

    private void loadPluginsLocked(Collection<Plugin> plugins) {
        assert lock.isHeldByCurrentThread() : "Lock is not held by current thread";

        LOGGER.debug("Loading plugins");
        for (final Plugin plugin : plugins) {
            try (var ignoredMdcPlugin = MDC.putCloseable(MDC_PLUGIN, plugin.getClass().getName())) {
                LOGGER.debug("Loading plugin");
                loadExtensionsForPlugin(plugin);

                LOGGER.debug("Plugin loaded successfully");
                loadedPluginByClass.put(plugin.getClass(), plugin);
            }
        }

        determineDefaultExtensions();

        assertRequiredExtensionPoints();
    }

    private void loadExtensionsForPlugin(Plugin plugin) {
        final Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories = plugin.extensionFactories();
        if (extensionFactories == null || extensionFactories.isEmpty()) {
            LOGGER.debug("Plugin does not define any extensions; Skipping");
            return;
        }

        for (final ExtensionFactory<? extends ExtensionPoint> extensionFactory : extensionFactories) {
            if (extensionFactory.extensionName() == null) {
                throw new IllegalStateException(
                        "%s does not define an extension name".formatted(
                                extensionFactory.getClass().getName()));
            }
            if (!EXTENSION_NAME_PATTERN.matcher(extensionFactory.extensionName()).matches()) {
                throw new IllegalStateException(
                        "%s defines an invalid extension name: %s".formatted(
                                extensionFactory.getClass().getName(), extensionFactory.extensionName()));
            }
            if (extensionFactory.extensionClass() == null) {
                throw new IllegalStateException(
                        "%s does not define an extension class".formatted(
                                extensionFactory.getClass().getName()));
            }

            // Prevent plugins from registering their extensions as non-concrete classes.
            // The purpose of tracking extension classes is to differentiate them from another,
            // which would be impossible if we allowed interfaces or abstract classes.
            if (extensionFactory.extensionClass().isInterface()
                    || Modifier.isAbstract(extensionFactory.extensionClass().getModifiers())) {
                throw new IllegalStateException("""
                        Class %s of extension %s from plugin %s is either abstract or an interface; \
                        Extension classes must be concrete""".formatted(extensionFactory.extensionClass().getName(),
                        extensionFactory.extensionName(), MDC.get(MDC_PLUGIN)));
            }

            final ExtensionPointMetadata extensionPointMetadata =
                    requireImplementsExtensionPoint(extensionFactory.extensionClass());

            try (var ignoredMdcExtensionPointName = MDC.putCloseable(MDC_EXTENSION_POINT_NAME, extensionPointMetadata.name());
                 var ignoredMdcExtensionPoint = MDC.putCloseable(MDC_EXTENSION_POINT, extensionPointMetadata.clazz().getName());
                 var ignoredMdcExtensionName = MDC.putCloseable(MDC_EXTENSION_NAME, extensionFactory.extensionName());
                 var ignoredMdcExtension = MDC.putCloseable(MDC_EXTENSION, extensionFactory.extensionClass().getName())) {
                loadExtension(plugin, extensionFactory, extensionPointMetadata);
            }
        }
    }

    private void loadExtension(
            Plugin plugin,
            ExtensionFactory<? extends ExtensionPoint> extensionFactory,
            ExtensionPointMetadata extensionPointMetadata) {
        final var extensionIdentity = new ExtensionIdentity(
                extensionPointMetadata.clazz(),
                extensionFactory.extensionName());

        // Prevent the same extension from being loaded from multiple plugins.
        if (pluginByExtensionIdentity.containsKey(extensionIdentity)) {
            final Plugin conflictingPlugin = pluginByExtensionIdentity.get(extensionIdentity);
            throw new IllegalStateException(
                    "Extension was already loaded from plugin %s".formatted(
                            conflictingPlugin.getClass().getName()));
        }

        if (extensionFactory.priority() < PRIORITY_HIGHEST) {
            throw new IllegalStateException("""
                    Extension %s from plugin %s has an invalid priority of %d; \
                    Allowed range is [%d..%d] (highest to lowest priority)\
                    """.formatted(MDC.get(MDC_EXTENSION), MDC.get(MDC_PLUGIN),
                    extensionFactory.priority(), PRIORITY_HIGHEST, PRIORITY_LOWEST)
            );
        }

        final @Nullable RuntimeConfigSpec runtimeConfigSpec =
                extensionFactory instanceof final RuntimeConfigurable rc
                        ? rc.runtimeConfigSpec()
                        : null;

        final var configRegistry = new ConfigRegistryImpl(
                jdbi,
                config,
                extensionPointMetadata.name(),
                extensionIdentity.name(),
                runtimeConfigSpec,
                runtimeConfigSpec != null
                        ? runtimeConfigMapper
                        : null,
                runtimeConfigSpec != null
                        ? secretResolver
                        : null);
        configRegistryByExtensionIdentity.put(extensionIdentity, configRegistry);

        if (runtimeConfigSpec != null) {
            final RuntimeConfig defaultRuntimeConfig = runtimeConfigSpec.defaultConfig();
            if (defaultRuntimeConfig == null) {
                throw new IllegalStateException("""
                        Extension %s from plugin %s has defined a runtime config class, \
                        but does not define a default config.\
                        """.formatted(MDC.get(MDC_EXTENSION), MDC.get(MDC_PLUGIN)));
            }

            LOGGER.debug("Creating runtime extension configs with defaults if necessary");
            if (!configRegistry.hasRuntimeConfig()) {
                final boolean updated = configRegistry.setRuntimeConfig(defaultRuntimeConfig);
                if (updated) {
                    LOGGER.debug("Created default runtime config");
                }
            }
        }

        final var keyValueStore = new KeyValueStoreImpl(
                jdbi,
                extensionPointMetadata.name(),
                extensionIdentity.name());

        final var extensionCacheManager = new NamespacedCacheManager(
                this.cacheManager,
                "%s.%s".formatted(
                        extensionPointMetadata.name(),
                        extensionIdentity.name()));

        final var serviceRegistry = new MutableServiceRegistry()
                .register(ConfigRegistry.class, configRegistry)
                .register(CacheManager.class, extensionCacheManager)
                .register(KeyValueStore.class, keyValueStore)
                .register(HttpClient.class, httpClient)
                .freeze();

        LOGGER.debug("Initializing extension");
        try {
            extensionFactory.init(serviceRegistry);
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "Failed to initialize extension %s from plugin %s".formatted(
                            MDC.get(MDC_EXTENSION), MDC.get(MDC_PLUGIN)), e);
        }

        factoriesByPlugin.computeIfAbsent(
                        plugin, ignored -> new ArrayList<>())
                .add(extensionFactory);
        extensionNamesByExtensionPointClass.computeIfAbsent(
                        extensionIdentity.extensionPointClass(),
                        ignored -> new HashSet<>())
                .add(extensionFactory.extensionName());
        factoryByExtensionIdentity.put(extensionIdentity, extensionFactory);
        pluginByExtensionIdentity.put(extensionIdentity, plugin);
    }

    private void determineDefaultExtensions() {
        for (final Class<? extends ExtensionPoint> extensionPointClass : extensionNamesByExtensionPointClass.keySet()) {
            final ExtensionPointMetadata extensionPointMetadata = metadataByExtensionPointClass.get(extensionPointClass);
            if (extensionPointMetadata == null) {
                throw new IllegalStateException("""
                        No specification exists for extension point %s; \
                        This is likely a logic error in the plugin loading procedure\
                        """.formatted(extensionPointClass.getName()));
            }

            try (var ignoredMdcExtensionPoint = MDC.putCloseable(MDC_EXTENSION_POINT, extensionPointClass.getName());
                 var ignoredMdcExtensionPointName = MDC.putCloseable(MDC_EXTENSION_POINT_NAME, extensionPointMetadata.name())) {
                LOGGER.debug("Determining default extension");

                final SequencedCollection<? extends ExtensionFactory<?>> factories = getFactories(extensionPointClass);
                if (factories == null || factories.isEmpty()) {
                    LOGGER.warn("No extension available; Skipping");
                    continue;
                }

                final String defaultExtensionName = config
                        .getOptionalValue("dt.%s.default-extension".formatted(extensionPointMetadata.name()), String.class)
                        .orElse(null);

                final ExtensionFactory<?> extensionFactory;
                if (defaultExtensionName == null) {
                    LOGGER.debug("No default extension configured; Choosing based on priority");
                    extensionFactory = factories.getFirst();
                    LOGGER.debug("Chose extension %s (%s) with priority %d as default".formatted(
                            extensionFactory.extensionName(),
                            extensionFactory.extensionClass().getName(),
                            extensionFactory.priority()));
                } else {
                    extensionFactory = factories.stream()
                            .filter(factory -> factory.extensionName().equals(defaultExtensionName))
                            .findFirst()
                            .orElseThrow(() -> new NoSuchExtensionException(extensionPointMetadata.name(), defaultExtensionName));
                    LOGGER.debug("Using extension %s (%s) as default".formatted(
                            extensionFactory.extensionName(), extensionFactory.extensionClass().getName()));
                }

                defaultFactoryByExtensionPointClass.put(extensionPointClass, extensionFactory);
            }
        }
    }

    private ExtensionPointMetadata requireKnownExtensionPoint(Class<? extends ExtensionPoint> extensionPointClass) {
        final ExtensionPointMetadata metadata = metadataByExtensionPointClass.get(extensionPointClass);
        if (metadata == null) {
            throw new NoSuchExtensionPointException(extensionPointClass);
        }

        return metadata;
    }

    private ExtensionPointMetadata requireImplementsExtensionPoint(Class<? extends ExtensionPoint> concreteExtensionClass) {
        for (final Class<? extends ExtensionPoint> extensionPointClass : metadataByExtensionPointClass.keySet()) {
            if (extensionPointClass.isAssignableFrom(concreteExtensionClass)) {
                return metadataByExtensionPointClass.get(extensionPointClass);
            }
        }

        throw new IllegalStateException(
                "Extension %s does not implement any known extension point".formatted(
                        concreteExtensionClass.getName()));
    }

    private void assertRequiredExtensionPoints() {
        for (final ExtensionPointMetadata metadata : metadataByExtensionPointClass.values()) {
            if (!metadata.required()) {
                continue;
            }

            try {
                getFactory(metadata.clazz());
            } catch (NoSuchExtensionException e) {
                throw new IllegalStateException(
                        "Extension point %s (%s) is required, but no extension is enabled".formatted(
                                metadata.name(), metadata.clazz().getName()));
            }
        }
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }

        lock.lock();
        try {
            unloadPluginsLocked();
            defaultFactoryByExtensionPointClass.clear();
            configRegistryByExtensionIdentity.clear();
            factoryByExtensionIdentity.clear();
            extensionNamesByExtensionPointClass.clear();
            metadataByExtensionPointClass.clear();
            factoriesByPlugin.clear();
            pluginByExtensionIdentity.clear();
            loadedPluginByClass.clear();
        } finally {
            lock.unlock();
        }
    }

    public boolean isClosed() {
        return closed.get();
    }

    private void unloadPluginsLocked() {
        assert lock.isHeldByCurrentThread() : "Lock is not held by current thread";

        // Unload plugins in reverse order in which they were loaded.
        for (final Plugin plugin : loadedPluginByClass.sequencedValues().reversed()) {
            try (var ignoredMdcPlugin = MDC.putCloseable(MDC_PLUGIN, plugin.getClass().getName())) {
                LOGGER.debug("Unloading plugin");
                unloadPlugin(plugin);

                LOGGER.debug("Plugin unloaded");
            }
        }
    }

    private void unloadPlugin(Plugin plugin) {
        final List<ExtensionFactory<?>> factories = factoriesByPlugin.get(plugin);
        if (factories == null || factories.isEmpty()) {
            LOGGER.debug("No extensions were loaded; Skipping");
            return;
        }

        // Close factories in reverse order in which they were initialized.
        for (final ExtensionFactory<?> extensionFactory : factories.reversed()) {
            final ExtensionPointMetadata extensionPointMetadata = requireImplementsExtensionPoint(extensionFactory.extensionClass());

            final String extensionPointClassName = extensionPointMetadata.clazz().getName();
            final String extensionClassName = extensionFactory.extensionClass().getName();

            try (var ignoredMdcExtensionPoint = MDC.putCloseable(MDC_EXTENSION_POINT, extensionPointClassName);
                 var ignoredMdcExtension = MDC.putCloseable(MDC_EXTENSION, extensionClassName)) {
                LOGGER.debug("Closing extension");
                extensionFactory.close();

                LOGGER.debug("Extension closed successfully");
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to close extension", e);
            }
        }
    }

}
