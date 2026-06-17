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
package org.dependencytrack.pkgmetadata;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;

final class MockPackageMetadataResolverPlugin implements Plugin {

    private final MockPackageMetadataResolverFactory factory;

    MockPackageMetadataResolverPlugin(
            AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef,
            AtomicReference<PackageArtifactMetadata> lastSeenPriorRef) {
        this.factory = new MockPackageMetadataResolverFactory(resolveFnRef, lastSeenPriorRef);
    }

    @Override
    public @NonNull Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(factory);
    }

    private static final class MockPackageMetadataResolver implements PackageMetadataResolver {

        private final AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef;
        private final AtomicReference<PackageArtifactMetadata> lastSeenPriorRef;

        MockPackageMetadataResolver(
                AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef,
                AtomicReference<PackageArtifactMetadata> lastSeenPriorRef) {
            this.resolveFnRef = resolveFnRef;
            this.lastSeenPriorRef = lastSeenPriorRef;
        }

        @Override
        public @Nullable PackageMetadata resolve(
                PackageURL purl,
                @Nullable PackageRepository repository,
                @Nullable PackageArtifactMetadata prior) {
            lastSeenPriorRef.set(prior);
            return resolveFnRef.get().apply(purl);
        }

    }

    private static final class MockPackageMetadataResolverFactory implements PackageMetadataResolverFactory {

        private final AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef;
        private final AtomicReference<PackageArtifactMetadata> lastSeenPriorRef;

        MockPackageMetadataResolverFactory(
                AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef,
                AtomicReference<PackageArtifactMetadata> lastSeenPriorRef) {
            this.resolveFnRef = resolveFnRef;
            this.lastSeenPriorRef = lastSeenPriorRef;
        }

        @Override
        public @NonNull String extensionName() {
            return "mock";
        }

        @Override
        public @NonNull Class<? extends PackageMetadataResolver> extensionClass() {
            return MockPackageMetadataResolver.class;
        }

        @Override
        public void init(@NonNull ServiceRegistry serviceRegistry) {
        }

        @Override
        public PackageMetadataResolver create() {
            return new MockPackageMetadataResolver(resolveFnRef, lastSeenPriorRef);
        }

        @Override
        public @Nullable PackageURL normalize(PackageURL purl) {
            if (!"maven".equals(purl.getType())) {
                return null;
            }
            if (purl.getQualifiers() != null && purl.getQualifiers().containsKey("type")) {
                return purl;
            }

            try {
                final var builder = aPackageURL()
                        .withType(purl.getType())
                        .withNamespace(purl.getNamespace())
                        .withName(purl.getName())
                        .withVersion(purl.getVersion())
                        .withQualifier("type", "jar");
                if (purl.getQualifiers() != null) {
                    for (final var qualifier : purl.getQualifiers().entrySet()) {
                        builder.withQualifier(qualifier.getKey(), qualifier.getValue());
                    }
                }

                return builder.build();
            } catch (MalformedPackageURLException e) {
                return purl;
            }
        }

        @Override
        public boolean requiresRepository() {
            return false;
        }

    }

}
