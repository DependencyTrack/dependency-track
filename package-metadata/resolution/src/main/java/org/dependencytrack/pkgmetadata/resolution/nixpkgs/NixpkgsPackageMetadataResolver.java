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

import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cache.CacheKeys;
import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

final class NixpkgsPackageMetadataResolver implements PackageMetadataResolver {

    private final NixpkgsPackageIndex packageIndex;
    private final Cache cache;

    NixpkgsPackageMetadataResolver(NixpkgsPackageIndex packageIndex, Cache cache) {
        this.packageIndex = packageIndex;
        this.cache = cache;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String cacheKey = CacheKeys.build(repository, purl.getName());

        final byte[] cached = cache.get(cacheKey);
        if (cached != null) {
            return new PackageMetadata(new String(cached, StandardCharsets.UTF_8), null, Instant.now(), null);
        }

        final String version = packageIndex.getVersion(purl.getName(), repository.url());
        if (version == null) {
            return null;
        }

        cache.put(cacheKey, version.getBytes(StandardCharsets.UTF_8));
        return new PackageMetadata(version, null, Instant.now(), null);
    }

}
