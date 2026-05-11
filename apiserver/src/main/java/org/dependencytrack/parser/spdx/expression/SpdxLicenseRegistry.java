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
package org.dependencytrack.parser.spdx.expression;

import jakarta.annotation.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * @since 5.0.0
 */
final class SpdxLicenseRegistry {

    record LicenseFamily(List<VersionGroup> versions) {

        private static LicenseFamily of(VersionGroup... groups) {
            return new LicenseFamily(List.of(groups));
        }

    }

    record VersionGroup(List<String> ids) {

        private static VersionGroup of(String... ids) {
            return new VersionGroup(List.of(ids));
        }

    }

    record Position(int familyIndex, int versionIndex) {
    }

    static final List<LicenseFamily> FAMILIES = List.of(
            LicenseFamily.of(
                    VersionGroup.of("AFL-1.1"),
                    VersionGroup.of("AFL-1.2"),
                    VersionGroup.of("AFL-2.0"),
                    VersionGroup.of("AFL-2.1"),
                    VersionGroup.of("AFL-3.0")),
            LicenseFamily.of(
                    VersionGroup.of("AGPL-1.0", "AGPL-1.0-only"),
                    VersionGroup.of("AGPL-3.0", "AGPL-3.0-only")),
            LicenseFamily.of(
                    VersionGroup.of("Apache-1.0"),
                    VersionGroup.of("Apache-1.1"),
                    VersionGroup.of("Apache-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("APSL-1.0"),
                    VersionGroup.of("APSL-1.1"),
                    VersionGroup.of("APSL-1.2"),
                    VersionGroup.of("APSL-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("Artistic-1.0"),
                    VersionGroup.of("Artistic-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("ASWF-Digital-Assets-1.0"),
                    VersionGroup.of("ASWF-Digital-Assets-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("BitTorrent-1.0"),
                    VersionGroup.of("BitTorrent-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("CC-BY-1.0"),
                    VersionGroup.of("CC-BY-2.0"),
                    VersionGroup.of("CC-BY-2.5"),
                    VersionGroup.of("CC-BY-3.0"),
                    VersionGroup.of("CC-BY-4.0")),
            LicenseFamily.of(
                    VersionGroup.of("CC-BY-NC-1.0"),
                    VersionGroup.of("CC-BY-NC-2.0"),
                    VersionGroup.of("CC-BY-NC-2.5"),
                    VersionGroup.of("CC-BY-NC-3.0"),
                    VersionGroup.of("CC-BY-NC-4.0")),
            LicenseFamily.of(
                    VersionGroup.of("CC-BY-NC-ND-1.0"),
                    VersionGroup.of("CC-BY-NC-ND-2.0"),
                    VersionGroup.of("CC-BY-NC-ND-2.5"),
                    VersionGroup.of("CC-BY-NC-ND-3.0"),
                    VersionGroup.of("CC-BY-NC-ND-4.0")),
            LicenseFamily.of(
                    VersionGroup.of("CC-BY-NC-SA-1.0"),
                    VersionGroup.of("CC-BY-NC-SA-2.0"),
                    VersionGroup.of("CC-BY-NC-SA-2.5"),
                    VersionGroup.of("CC-BY-NC-SA-3.0"),
                    VersionGroup.of("CC-BY-NC-SA-4.0")),
            LicenseFamily.of(
                    VersionGroup.of("CC-BY-ND-1.0"),
                    VersionGroup.of("CC-BY-ND-2.0"),
                    VersionGroup.of("CC-BY-ND-2.5"),
                    VersionGroup.of("CC-BY-ND-3.0"),
                    VersionGroup.of("CC-BY-ND-4.0")),
            LicenseFamily.of(
                    VersionGroup.of("CC-BY-SA-1.0"),
                    VersionGroup.of("CC-BY-SA-2.0"),
                    VersionGroup.of("CC-BY-SA-2.5"),
                    VersionGroup.of("CC-BY-SA-3.0"),
                    VersionGroup.of("CC-BY-SA-4.0")),
            LicenseFamily.of(
                    VersionGroup.of("CDDL-1.0"),
                    VersionGroup.of("CDDL-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("CECILL-1.0"),
                    VersionGroup.of("CECILL-1.1"),
                    VersionGroup.of("CECILL-2.0"),
                    VersionGroup.of("CECILL-2.1")),
            LicenseFamily.of(
                    VersionGroup.of("DRL-1.0"),
                    VersionGroup.of("DRL-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("ECL-1.0"),
                    VersionGroup.of("ECL-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("EFL-1.0"),
                    VersionGroup.of("EFL-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("EPL-1.0"),
                    VersionGroup.of("EPL-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("EUPL-1.0"),
                    VersionGroup.of("EUPL-1.1"),
                    VersionGroup.of("EUPL-1.2")),
            LicenseFamily.of(
                    VersionGroup.of("GFDL-1.1", "GFDL-1.1-only"),
                    VersionGroup.of("GFDL-1.2", "GFDL-1.2-only"),
                    VersionGroup.of("GFDL-1.3", "GFDL-1.3-only")),
            LicenseFamily.of(
                    VersionGroup.of("GPL-1.0", "GPL-1.0-only"),
                    VersionGroup.of("GPL-2.0", "GPL-2.0-only"),
                    VersionGroup.of("GPL-3.0", "GPL-3.0-only")),
            LicenseFamily.of(
                    VersionGroup.of("HP-1986"),
                    VersionGroup.of("HP-1989")),
            LicenseFamily.of(
                    VersionGroup.of("LGPL-2.0", "LGPL-2.0-only"),
                    VersionGroup.of("LGPL-2.1", "LGPL-2.1-only"),
                    VersionGroup.of("LGPL-3.0", "LGPL-3.0-only")),
            LicenseFamily.of(
                    VersionGroup.of("LPL-1.0"),
                    VersionGroup.of("LPL-1.02")),
            LicenseFamily.of(
                    VersionGroup.of("LPPL-1.0"),
                    VersionGroup.of("LPPL-1.1"),
                    VersionGroup.of("LPPL-1.2"),
                    VersionGroup.of("LPPL-1.3a"),
                    VersionGroup.of("LPPL-1.3c")),
            LicenseFamily.of(
                    VersionGroup.of("MPL-1.0"),
                    VersionGroup.of("MPL-1.1"),
                    VersionGroup.of("MPL-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("NPL-1.0"),
                    VersionGroup.of("NPL-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("OFL-1.0"),
                    VersionGroup.of("OFL-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("OLDAP-1.1"),
                    VersionGroup.of("OLDAP-1.2"),
                    VersionGroup.of("OLDAP-1.3"),
                    VersionGroup.of("OLDAP-1.4"),
                    VersionGroup.of("OLDAP-2.0"),
                    VersionGroup.of("OLDAP-2.0.1"),
                    VersionGroup.of("OLDAP-2.1"),
                    VersionGroup.of("OLDAP-2.2"),
                    VersionGroup.of("OLDAP-2.2.1"),
                    VersionGroup.of("OLDAP-2.2.2"),
                    VersionGroup.of("OLDAP-2.3"),
                    VersionGroup.of("OLDAP-2.4"),
                    VersionGroup.of("OLDAP-2.5"),
                    VersionGroup.of("OLDAP-2.6"),
                    VersionGroup.of("OLDAP-2.7"),
                    VersionGroup.of("OLDAP-2.8")),
            LicenseFamily.of(
                    VersionGroup.of("OSL-1.0"),
                    VersionGroup.of("OSL-1.1"),
                    VersionGroup.of("OSL-2.0"),
                    VersionGroup.of("OSL-2.1"),
                    VersionGroup.of("OSL-3.0")),
            LicenseFamily.of(
                    VersionGroup.of("PHP-3.0"),
                    VersionGroup.of("PHP-3.01")),
            LicenseFamily.of(
                    VersionGroup.of("RPL-1.1"),
                    VersionGroup.of("RPL-1.5")),
            LicenseFamily.of(
                    VersionGroup.of("SGI-B-1.0"),
                    VersionGroup.of("SGI-B-1.1"),
                    VersionGroup.of("SGI-B-2.0")),
            LicenseFamily.of(
                    VersionGroup.of("YPL-1.0"),
                    VersionGroup.of("YPL-1.1")),
            LicenseFamily.of(
                    VersionGroup.of("ZPL-1.1"),
                    VersionGroup.of("ZPL-2.0"),
                    VersionGroup.of("ZPL-2.1")),
            LicenseFamily.of(
                    VersionGroup.of("Zimbra-1.3"),
                    VersionGroup.of("Zimbra-1.4")),
            LicenseFamily.of(
                    VersionGroup.of("bzip2-1.0.5"),
                    VersionGroup.of("bzip2-1.0.6")));

    static final Map<String, String> WITH_COMPOUNDS;
    private static final Map<String, Position> INDEX;

    static {
        final var withCompounds = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        withCompounds.put("GPL-2.0-with-autoconf-exception", "GPL-2.0-only WITH Autoconf-exception-2.0");
        withCompounds.put("GPL-2.0-with-bison-exception", "GPL-2.0-only WITH Bison-exception-2.2");
        withCompounds.put("GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0");
        withCompounds.put("GPL-2.0-with-font-exception", "GPL-2.0-only WITH Font-exception-2.0");
        withCompounds.put("GPL-2.0-with-GCC-exception", "GPL-2.0-only WITH GCC-exception-2.0");
        withCompounds.put("GPL-3.0-with-autoconf-exception", "GPL-3.0-only WITH Autoconf-exception-3.0");
        withCompounds.put("GPL-3.0-with-GCC-exception", "GPL-3.0-only WITH GCC-exception-3.1");
        WITH_COMPOUNDS = Collections.unmodifiableMap(withCompounds);

        final var index = new TreeMap<String, Position>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 0; i < FAMILIES.size(); i++) {
            final LicenseFamily family = FAMILIES.get(i);
            for (int j = 0; j < family.versions().size(); j++) {
                for (final String id : family.versions().get(j).ids()) {
                    index.put(id, new Position(i, j));
                }
            }
        }
        INDEX = Collections.unmodifiableMap(index);
    }

    private SpdxLicenseRegistry() {
    }

    static @Nullable Position lookup(String id) {
        return INDEX.get(id);
    }

    static @Nullable String resolveWithCompound(String id) {
        return WITH_COMPOUNDS.get(id);
    }

}
