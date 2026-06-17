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
package org.dependencytrack.vulndatasource;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.ServletContext;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class VulnDataSourceMirrorServiceBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bindFactory(VulnDataSourceMirrorServiceFactory.class)
                .to(VulnDataSourceMirrorService.class)
                .in(Singleton.class);
    }

    private static final class VulnDataSourceMirrorServiceFactory implements Factory<VulnDataSourceMirrorService> {

        private final ServletContext servletContext;

        @Inject
        private VulnDataSourceMirrorServiceFactory(ServletContext servletContext) {
            this.servletContext = servletContext;
        }

        @Override
        public VulnDataSourceMirrorService provide() {
            final var pluginManager = (PluginManager) servletContext.getAttribute(PluginManager.class.getName());
            final var dexEngine = (DexEngine) servletContext.getAttribute(DexEngine.class.getName());
            return new VulnDataSourceMirrorService(
                    requireNonNull(pluginManager, "pluginManager is not initialized"),
                    requireNonNull(dexEngine, "dexEngine is not initialized"));
        }

        @Override
        public void dispose(VulnDataSourceMirrorService instance) {
        }

    }

}
