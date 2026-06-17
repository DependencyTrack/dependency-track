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
package org.dependencytrack.policy.cel;

import dev.cel.common.types.CelType;

import java.util.List;
import java.util.Map;

import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.COMPARE_AGE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.DEPENDS_ON;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.HAS_PACKAGE_ARTIFACT_HASH_MISMATCH;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_DIRECT_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.IS_EXCLUSIVE_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.MATCHES_RANGE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.Function.VERSION_DISTANCE;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VULNERABILITY;

final class CelPolicyRequirements {

    static final Map<String, Map<CelType, List<String>>> FUNCTION_FIELD_REQUIREMENTS = Map.ofEntries(
            Map.entry(DEPENDS_ON.functionName(), Map.of(TYPE_PROJECT, List.of("uuid"), TYPE_COMPONENT, List.of("uuid"))),
            Map.entry(IS_DEPENDENCY_OF.functionName(), Map.of(TYPE_COMPONENT, List.of("uuid"))),
            Map.entry(IS_EXCLUSIVE_DEPENDENCY_OF.functionName(), Map.of(TYPE_COMPONENT, List.of("uuid"))),
            Map.entry(IS_DIRECT_DEPENDENCY_OF.functionName(), Map.of(TYPE_COMPONENT, List.of("uuid"))),
            Map.entry(MATCHES_RANGE.functionName(), Map.of(TYPE_PROJECT, List.of("version"), TYPE_COMPONENT, List.of("version"))),
            Map.entry(VERSION_DISTANCE.functionName(), Map.of(TYPE_COMPONENT, List.of("purl", "uuid", "version", "latest_version"))),
            Map.entry(COMPARE_AGE.functionName(), Map.of(TYPE_COMPONENT, List.of("purl", "published_at"))),
            Map.entry(
                    HAS_PACKAGE_ARTIFACT_HASH_MISMATCH.functionName(),
                    Map.of(
                            TYPE_COMPONENT,
                            List.of(
                                    "md5",
                                    "sha1",
                                    "sha256",
                                    "sha512",
                                    "package_artifact_md5",
                                    "package_artifact_sha1",
                                    "package_artifact_sha256",
                                    "package_artifact_sha512"))));

    static final Map<CelType, Map<String, List<String>>> FIELD_EXPANSIONS = Map.of(
            TYPE_VULNERABILITY, Map.of(
                    "severity", List.of(
                            "cvssv2_base_score",
                            "cvssv3_base_score",
                            "cvssv4_score",
                            "owasp_rr_likelihood_score",
                            "owasp_rr_technical_impact_score",
                            "owasp_rr_business_impact_score")));

    private CelPolicyRequirements() {
    }

}
