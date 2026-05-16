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
package org.dependencytrack.pkgmetadata.resolution.api;

import com.github.packageurl.PackageURL;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.jspecify.annotations.Nullable;

/**
 * An {@link ExtensionPoint} for package metadata resolvers.
 *
 * @since 5.0.0
 */
@ExtensionPointSpec(name = "package-metadata-resolver", required = false)
public interface PackageMetadataResolver extends ExtensionPoint {

    /**
     * Resolve metadata for the given PURL, optionally against a specific repository.
     * <p>
     * Implementations are expected to make aggressive use of caching,
     * and respect rate limits of upstream repositories. When a transient
     * failure is detected (rate limiting, server errors, connection failures),
     * a {@link RetryableResolutionException} should be thrown.
     * <p>
     * The caller is responsible for ensuring that {@code prior}, when non-null, was resolved
     * against the same repository as the one currently being attempted. Resolvers decide
     * whether the prior data is safe to reuse (e.g. only for stable versions). Resolvers
     * that cannot benefit from the hint may ignore the parameter entirely.
     *
     * @param purl       The package URL to resolve metadata for.
     * @param repository The repository to resolve against, or {@code null} for standalone resolvers.
     * @param prior      Previously resolved artifact-level metadata for the same PURL and repository,
     *                   or {@code null} if no prior data is available.
     * @return The resolved metadata, or {@code null} if no metadata could be resolved.
     */
    @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository,
            @Nullable PackageArtifactMetadata prior) throws InterruptedException;

}
