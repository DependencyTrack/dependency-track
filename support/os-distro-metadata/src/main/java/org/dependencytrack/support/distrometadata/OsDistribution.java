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
package org.dependencytrack.support.distrometadata;

import com.github.packageurl.PackageURL;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * @since 4.14.0
 */
public sealed interface OsDistribution permits AlpineDistribution, DebianDistribution, UbuntuDistribution {

    String purlQualifierValue();

    boolean matches(OsDistribution other);

    static @Nullable OsDistribution of(@Nullable PackageURL purl) {
        if (purl == null) {
            return null;
        }

        final Map<String, String> qualifiers = purl.getQualifiers();
        if (qualifiers == null) {
            return null;
        }

        final String distroQualifier = qualifiers.get("distro");
        if (distroQualifier == null || distroQualifier.isEmpty()) {
            return null;
        }

        if ("apk".equals(purl.getType())) {
            return AlpineDistribution.of(distroQualifier);
        }

        if ("deb".equals(purl.getType())) {
            if ("debian".equalsIgnoreCase(purl.getNamespace())) {
                return DebianDistribution.of(distroQualifier);
            }
            if ("ubuntu".equalsIgnoreCase(purl.getNamespace())) {
                return UbuntuDistribution.of(distroQualifier);
            }
        }

        return null;
    }

}
