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
package org.dependencytrack.vulndatasource.osv;

import org.dependencytrack.support.distrometadata.AlpineDistribution;
import org.dependencytrack.support.distrometadata.DebianDistribution;
import org.dependencytrack.support.distrometadata.OsDistribution;
import org.dependencytrack.support.distrometadata.RedhatDistribution;
import org.dependencytrack.support.distrometadata.UbuntuDistribution;
import org.jspecify.annotations.Nullable;

final class OsvEcosystems {

    private OsvEcosystems() {
    }

    static @Nullable OsDistribution toOsDistribution(@Nullable String ecosystem) {
        if (ecosystem == null || ecosystem.isEmpty()) {
            return null;
        }

        final int colonIndex = ecosystem.indexOf(':');
        if (colonIndex == -1 || colonIndex == ecosystem.length() - 1) {
            return null;
        }

        final String ecosystemName = ecosystem.substring(0, colonIndex);
        final String suffix = ecosystem.substring(colonIndex + 1);

        return switch (ecosystemName.toLowerCase()) {
            case "alpine" -> AlpineDistribution.ofVersion(suffix);
            case "debian" -> DebianDistribution.of(suffix);
            case "ubuntu" -> {
                // Strip :LTS and :Pro variants. Matches OSV's own normalization:
                // https://github.com/google/osv.dev/blob/60cf1d74ec77a8f40589d2bbb3cfd241a545f807/osv/ecosystems/_ecosystems.py#L154-L160
                final String versionOrSeries = suffix.replaceAll(":(LTS|Pro)", "");
                yield UbuntuDistribution.of(versionOrSeries);
            }
            // Red Hat carries a :<CPE> suffix scoping the RPM to a specific
            // Red Hat product stream, e.g. "Red Hat:rhel_aus:8.4::appstream".
            // The CPE is everything after the ecosystem name; its RHEL major
            // version is the comparable scope.
            // https://ossf.github.io/osv-schema/#defined-ecosystems
            case "red hat", "redhat" -> RedhatDistribution.ofCpe(suffix);
            default -> null;
        };
    }

}
