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
package org.dependencytrack.plugin;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.ServletContext;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class PluginManagerBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bindFactory(PluginManagerFactory.class)
                .to(PluginManager.class)
                .in(Singleton.class);
    }

    private static final class PluginManagerFactory implements Factory<PluginManager> {

        private final ServletContext servletContext;

        @Inject
        private PluginManagerFactory(ServletContext servletContext) {
            this.servletContext = servletContext;
        }

        @Override
        public PluginManager provide() {
            final var instance = (PluginManager) servletContext.getAttribute(PluginManager.class.getName());
            return requireNonNull(instance, "pluginManager is not initialized");
        }

        @Override
        public void dispose(PluginManager instance) {
            // Lifecycle is managed by PluginInitializer.
        }

    }

}
