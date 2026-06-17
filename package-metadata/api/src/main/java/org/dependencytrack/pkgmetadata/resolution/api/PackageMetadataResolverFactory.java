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
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.jspecify.annotations.Nullable;

/**
 * An {@link ExtensionFactory} for creating {@link PackageMetadataResolver} instances.
 *
 * @since 5.0.0
 */
public interface PackageMetadataResolverFactory extends ExtensionFactory<PackageMetadataResolver> {

    @Override
    default int priority() {
        return 0;
    }

    /**
     * Normalize the given PURL for resolution purposes.
     *
     * @param purl the package URL to normalize.
     * @return A normalized PURL with only relevant qualifiers retained if this
     * resolver supports the given PURL, or {@code null} if not supported.
     */
    @Nullable PackageURL normalize(PackageURL purl);

    /**
     * @return {@code true} if this resolver requires a repository.
     */
    boolean requiresRepository();

}
