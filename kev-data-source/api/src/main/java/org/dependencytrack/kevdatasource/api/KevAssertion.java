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
package org.dependencytrack.kevdatasource.api;

import com.fasterxml.jackson.databind.JsonNode;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/// A single assertion that a vulnerability is known to be exploited.
///
/// @param vulnSource      Source of the asserted vulnerability identifier (e.g. `NVD`).
/// @param vulnId          The asserted vulnerability identifier (e.g. `CVE-2021-44228`).
/// @param publishedAt     When the assertion was published by the source, if known.
/// @param requiredAction  Free-form remediation guidance provided by the source, if any.
/// @param knownRansomware Whether the vulnerability is known to be used in ransomware campaigns.
///                        `null` when the source does not report this signal, which is
///                        distinct from an explicit `false`.
/// @param description     Short description provided by the source, if any.
/// @param raw             The source's raw record for this assertion, as a JSON tree.
///                        `null` when the source has no original record to retain.
/// @since 5.1.0
public record KevAssertion(
        String vulnSource,
        String vulnId,
        @Nullable Instant publishedAt,
        @Nullable String requiredAction,
        @Nullable Boolean knownRansomware,
        @Nullable String description,
        @Nullable JsonNode raw) {

    public KevAssertion {
        requireNonNull(vulnSource, "vulnSource must not be null");
        requireNonNull(vulnId, "vulnId must not be null");
    }

}
