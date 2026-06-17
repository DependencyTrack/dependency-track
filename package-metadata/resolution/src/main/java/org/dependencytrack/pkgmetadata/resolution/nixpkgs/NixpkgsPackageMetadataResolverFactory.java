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
package org.dependencytrack.pkgmetadata.resolution.nixpkgs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.jspecify.annotations.Nullable;

import java.net.http.HttpClient;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

public final class NixpkgsPackageMetadataResolverFactory implements PackageMetadataResolverFactory {

    private @Nullable NixpkgsPackageIndex packageIndex;
    private @Nullable Cache cache;

    @Override
    public String extensionName() {
        return "nixpkgs";
    }

    @Override
    public Class<? extends PackageMetadataResolver> extensionClass() {
        return NixpkgsPackageMetadataResolver.class;
    }

    @Override
    public @Nullable PackageURL normalize(PackageURL purl) {
        if (!"nixpkgs".equals(purl.getType())
                || purl.getName() == null
                || purl.getVersion() == null) {
            return null;
        }

        try {
            return aPackageURL()
                    .withType(purl.getType())
                    .withNamespace(purl.getNamespace())
                    .withName(purl.getName())
                    .withVersion(purl.getVersion())
                    .build();
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    @Override
    public boolean requiresRepository() {
        return true;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        packageIndex = new NixpkgsPackageIndex(serviceRegistry.require(HttpClient.class), new ObjectMapper().getFactory());
        cache = serviceRegistry.require(CacheManager.class).getCache("responses");
    }

    @Override
    public PackageMetadataResolver create() {
        return new NixpkgsPackageMetadataResolver(packageIndex, cache);
    }

}
