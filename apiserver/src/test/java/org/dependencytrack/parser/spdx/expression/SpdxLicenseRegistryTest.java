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

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.common.Mappers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class SpdxLicenseRegistryTest {

    private static final Set<String> EXCLUDED_DEPRECATED = Set.of(
            "BSD-2-Clause-FreeBSD",
            "BSD-2-Clause-NetBSD",
            "Net-SNMP",
            "Nunit",
            "StandardML-NJ",
            "eCos-2.0",
            "wxWindows");
    private static final Pattern VERSIONED_ID = Pattern.compile("^(.+-)\\d+(?:\\.\\d+)+(-only|-or-later)?$");

    private static Set<String> registeredIds;
    private static Set<String> familyPrefixes;
    private static Set<String> deprecatedIds;
    private static Set<String> allIds;

    @BeforeAll
    static void setUp() throws IOException {
        registeredIds = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        familyPrefixes = new HashSet<>();

        for (final var family : SpdxLicenseRegistry.FAMILIES) {
            for (final SpdxLicenseRegistry.VersionGroup group : family.versions()) {
                registeredIds.addAll(group.ids());

                for (final String id : group.ids()) {
                    final var matcher = VERSIONED_ID.matcher(id);
                    if (matcher.find()) {
                        familyPrefixes.add(matcher.group(1).toLowerCase());
                    }
                }
            }
        }

        registeredIds.addAll(SpdxLicenseRegistry.WITH_COMPOUNDS.keySet());

        final JsonNode root;
        try (final InputStream is = SpdxLicenseRegistryTest.class.getClassLoader()
                .getResourceAsStream("license-list-data/json/licenses.json")) {
            assertThat(is).isNotNull();
            root = Mappers.jsonMapper().readTree(is);
        }

        deprecatedIds = new HashSet<>();
        allIds = new HashSet<>();
        for (final JsonNode license : root.get("licenses")) {
            final String id = license.get("licenseId").asText();
            allIds.add(id);
            if (license.get("isDeprecatedLicenseId").asBoolean()) {
                deprecatedIds.add(id);
            }
        }
    }

    @Test
    void shouldCoverAllDeprecatedLicenseIds() {
        final Set<String> uncovered = deprecatedIds.stream()
                .filter(id -> !id.endsWith("+"))
                .filter(id -> !EXCLUDED_DEPRECATED.contains(id))
                .filter(id -> !registeredIds.contains(id))
                .collect(HashSet::new, HashSet::add, HashSet::addAll);

        assertThat(uncovered)
                .as("""
                        Deprecated IDs not covered by SpdxLicenseRegistry. \
                        Add to a family, WITH_COMPOUNDS, or EXCLUDED_DEPRECATED.""")
                .isEmpty();
    }

    @Test
    void shouldCoverAllVersionedLicenseIdsInKnownFamilies() {
        // For every known family prefix, check that all SPDX IDs matching
        // PREFIX-VERSION(-only) are registered. Excludes -or-later (handled by suffix stripping),
        // "+" (handled by parser), "-with-" (handled by compound resolution),
        // and jurisdiction / variant suffixes (e.g. CC-BY-3.0-DE).
        final Set<String> uncovered = allIds.stream()
                .filter(id -> !registeredIds.contains(id))
                .filter(id -> !id.endsWith("+") && !id.endsWith("-or-later") && !id.contains("-with-"))
                .filter(id -> {
                    final var matcher = VERSIONED_ID.matcher(id);
                    return matcher.find() && familyPrefixes.contains(matcher.group(1).toLowerCase());
                })
                .collect(HashSet::new, HashSet::add, HashSet::addAll);

        assertThat(uncovered)
                .as("""
                        License IDs matching a known family prefix but missing from SpdxLicenseRegistry. \
                        Add to the appropriate family's version group.""")
                .isEmpty();
    }

}
