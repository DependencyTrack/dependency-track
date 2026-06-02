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
package org.dependencytrack.pkgmetadata.resolution.github;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.jspecify.annotations.Nullable;

import java.net.http.HttpClient;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

public final class GithubPackageMetadataResolverFactory implements PackageMetadataResolverFactory {

    private @Nullable ObjectMapper objectMapper;
    private @Nullable CachingHttpClient cachingHttpClient;

    @Override
    public String extensionName() {
        return "github";
    }

    @Override
    public Class<? extends PackageMetadataResolver> extensionClass() {
        return GithubPackageMetadataResolver.class;
    }

    @Override
    public @Nullable PackageURL normalize(PackageURL purl) {
        if (!PackageURL.StandardTypes.GITHUB.equals(purl.getType())
                || purl.getNamespace() == null
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
        objectMapper = new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        cachingHttpClient = new CachingHttpClient(
                serviceRegistry.require(HttpClient.class),
                serviceRegistry.require(CacheManager.class).getCache("responses"));
    }

    @Override
    public PackageMetadataResolver create() {
        return new GithubPackageMetadataResolver(objectMapper, cachingHttpClient);
    }

}
