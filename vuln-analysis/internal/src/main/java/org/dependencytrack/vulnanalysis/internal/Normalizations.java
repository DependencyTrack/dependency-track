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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.PackageURL;

import java.util.regex.Pattern;

/// @since 5.2.0
final class Normalizations {

    private static final Pattern PYPI_NAME_SEPARATORS = Pattern.compile("[-_.]+");

    private Normalizations() {}

    /// Applies type-specific normalization rules to the name of a given [PackageURL].
    static String normalizedPackageName(PackageURL purl) {
        // PEP 503 (https://peps.python.org/pep-0503/#normalized-names):
        //   "The name should be lowercased with all runs of the characters
        //   `.`, `-`, or `_` replaced with a single `-` character."
        //
        // Note that packageurl-java already lowercases names of PyPI packages.
        if (PackageURL.StandardTypes.PYPI.equals(purl.getType())) {
            return PYPI_NAME_SEPARATORS.matcher(purl.getName()).replaceAll("-");
        }

        return purl.getName();
    }
}
