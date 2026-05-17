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
package org.dependencytrack.resources.v2;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import alpine.server.filters.HeaderFilter;
import alpine.server.filters.RequestIdFilter;
import alpine.server.filters.RequestMdcEnrichmentFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.ext.ContextResolver;
import org.dependencytrack.cache.CacheManagerBinder;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.dex.DexEngineBinder;
import org.dependencytrack.filestorage.FileStorageBinder;
import org.dependencytrack.filters.DeprecationResponseFilter;
import org.dependencytrack.filters.JerseyMetricsApplicationEventListener;
import org.dependencytrack.plugin.PluginManagerBinder;
import org.dependencytrack.secret.SecretManagerBinder;
import org.dependencytrack.vulndatasource.VulnDataSourceMirrorServiceBinder;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.media.multipart.MultiPartFeature;

import static org.glassfish.jersey.server.ServerProperties.PROVIDER_PACKAGES;
import static org.glassfish.jersey.server.ServerProperties.PROVIDER_SCANNING_RECURSIVE;
import static org.glassfish.jersey.server.ServerProperties.WADL_FEATURE_DISABLE;

/**
 * @since 5.0.0
 */
public final class ResourceConfig extends org.glassfish.jersey.server.ResourceConfig {

    public ResourceConfig() {
        // Only scan the v2 package for providers, register everything else manually.
        // This gives us more flexibility to pick-and-choose, and potentially configure
        // specific features that do not necessarily overlap with v1.
        property(PROVIDER_PACKAGES, getClass().getPackageName());
        property(PROVIDER_SCANNING_RECURSIVE, true);
        property(WADL_FEATURE_DISABLE, true);

        register((ContextResolver<ObjectMapper>) type -> Mappers.jsonMapper());
        register(new AbstractBinder() {
            @Override
            protected void configure() {
                bind(Mappers.jsonMapper()).to(ObjectMapper.class);
            }
        });

        register(ApiFilter.class);
        register(AuthenticationFeature.class);
        register(AuthorizationFeature.class);
        register(DeprecationResponseFilter.class);
        register(HeaderFilter.class);
        register(JacksonFeature.withoutExceptionMappers());
        register(JerseyMetricsApplicationEventListener.class);
        register(MultiPartFeature.class);
        register(RequestIdFilter.class);
        register(RequestMdcEnrichmentFilter.class);

        register(CacheManagerBinder.class);
        register(DexEngineBinder.class);
        register(FileStorageBinder.class);
        register(PluginManagerBinder.class);
        register(SecretManagerBinder.class);
        register(VulnDataSourceMirrorServiceBinder.class);
    }

}

