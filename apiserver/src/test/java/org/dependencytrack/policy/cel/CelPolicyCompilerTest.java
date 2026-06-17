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

import dev.cel.common.CelValidationException;
import dev.cel.common.types.CelType;
import org.dependencytrack.policy.cel.CelPolicyCompiler.CacheMode;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VULNERABILITY;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CelPolicyCompilerTest {

    @Test
    void shouldReturnCachedProgramWhenCacheModeIsCache() throws Exception {
        final var compiler = new CelPolicyCompiler(CelPolicyType.COMPONENT);
        final String scriptSrc = """
                component.name == "foo"
                """;

        final CelPolicyProgram first = compiler.compile(scriptSrc, CacheMode.CACHE);
        final CelPolicyProgram second = compiler.compile(scriptSrc, CacheMode.CACHE);

        assertThat(second).isSameAs(first);
    }

    @Test
    void shouldNotCacheWhenCacheModeIsNoCache() throws Exception {
        final var compiler = new CelPolicyCompiler(CelPolicyType.COMPONENT);
        final String scriptSrc = """
                component.name == "foo"
                """;

        final CelPolicyProgram first = compiler.compile(scriptSrc, CacheMode.NO_CACHE);
        final CelPolicyProgram second = compiler.compile(scriptSrc, CacheMode.NO_CACHE);

        assertThat(second).isNotSameAs(first);
    }

    @Test
    void testRequirementsAnalysis() throws Exception {
        final CelPolicyProgram compiledProgram = CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                component.resolved_license.groups.exists(licenseGroup, licenseGroup.name == "Permissive")
                  && vulns.exists(vuln, vuln.severity in ["HIGH", "CRITICAL"] && has(vuln.aliases))
                  && project.depends_on(v1.Component{name: "foo"})
                """, CacheMode.NO_CACHE);

        final Map<CelType, Collection<String>> requirements = compiledProgram.getRequirements().asMap();
        assertThat(requirements).containsOnlyKeys(TYPE_COMPONENT, TYPE_LICENSE, TYPE_LICENSE_GROUP, TYPE_PROJECT, TYPE_VULNERABILITY);

        assertThat(requirements.get(TYPE_COMPONENT)).containsOnly("resolved_license");
        assertThat(requirements.get(TYPE_LICENSE)).containsOnly("groups");
        assertThat(requirements.get(TYPE_LICENSE_GROUP)).containsOnly("name");
        assertThat(requirements.get(TYPE_PROJECT)).containsOnly("uuid"); // Implicit through project.depends_on
        assertThat(requirements.get(TYPE_VULNERABILITY)).containsOnly(
                "aliases",
                // Scores are necessary to calculate severity...
                "cvssv2_base_score",
                "cvssv3_base_score",
                "cvssv4_score",
                "owasp_rr_likelihood_score",
                "owasp_rr_technical_impact_score",
                "owasp_rr_business_impact_score",
                "severity");
    }

    @Test
    void testRequirementsAnalysisWithFieldAccessInList() throws Exception {
        final CelPolicyProgram compiledProgram = CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                [component.name, project.name].exists(name, name == "foo")
                """, CacheMode.NO_CACHE);

        final Map<CelType, Collection<String>> requirements = compiledProgram.getRequirements().asMap();
        assertThat(requirements).containsOnlyKeys(TYPE_COMPONENT, TYPE_PROJECT);
        assertThat(requirements.get(TYPE_COMPONENT)).containsOnly("name");
        assertThat(requirements.get(TYPE_PROJECT)).containsOnly("name");
    }

    @Test
    void testRequirementsAnalysisWithFieldAccessInStructValue() throws Exception {
        final CelPolicyProgram compiledProgram = CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                project.depends_on(v1.Component{name: component.name})
                """, CacheMode.NO_CACHE);

        final Map<CelType, Collection<String>> requirements = compiledProgram.getRequirements().asMap();
        assertThat(requirements).containsOnlyKeys(TYPE_COMPONENT, TYPE_PROJECT);
        assertThat(requirements.get(TYPE_COMPONENT)).containsOnly("name");
        assertThat(requirements.get(TYPE_PROJECT)).containsOnly("uuid");
    }

    @Test
    void testRequirementsAnalysisWithFieldAccessInMapKey() throws Exception {
        final CelPolicyProgram compiledProgram = CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                {component.name: project.name}.size() > 0
                """, CacheMode.NO_CACHE);

        final Map<CelType, Collection<String>> requirements = compiledProgram.getRequirements().asMap();
        assertThat(requirements).containsOnlyKeys(TYPE_COMPONENT, TYPE_PROJECT);
        assertThat(requirements.get(TYPE_COMPONENT)).containsOnly("name");
        assertThat(requirements.get(TYPE_PROJECT)).containsOnly("name");
    }

    @Test
    void testVisitVersRangeCheck() {
        var exception = assertThrows(CelValidationException.class, () -> CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                project.name == "foo" && project.matches_range("vers:generic<1")
                  && project.depends_on(v1.Component{
                       version: "vers:maven/>0|>1"
                     })
                """, CacheMode.NO_CACHE));
        assertThat(exception.getErrors()).hasSize(3);
        assertThat(exception.getErrors().get(0).getMessage()).contains("vers string does not contain a versioning scheme separator");
        assertThat(exception.getErrors().get(1).getMessage()).contains("Querying by version range without providing an additional field to filter on is not allowed");
        assertThat(exception.getErrors().get(2).getMessage()).contains("Invalid range");

        // This expression has a type error (comparing bool to string),
        // so it fails at type-checking before vers validation runs.
        exception = assertThrows(CelValidationException.class, () -> CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                component.matches_range("vers:generic<1") == "foo" && project.matches_range("vers:generic<1")
                """, CacheMode.NO_CACHE));
        assertThat(exception.getErrors()).hasSizeGreaterThanOrEqualTo(1);
        assertThat(exception.getErrors().getFirst().getMessage()).contains("found no matching overload for '_==_'");

        exception = assertThrows(CelValidationException.class, () -> CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                component.name == "foo" || vulns.exists(vuln, vuln.id == "foo" && component.matches_range("versgeneric/<1"))
                """, CacheMode.NO_CACHE));
        assertThat(exception.getErrors()).hasSize(1);
        assertThat(exception.getErrors().getFirst().getMessage()).contains("vers string does not contain a URI scheme separator");

        assertDoesNotThrow(() -> CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                project.matches_range("vers:generic/<1")
                """, CacheMode.NO_CACHE));
    }

    @Test
    void shouldRejectInvalidSpdxExpressionLiteral() {
        final var exception = assertThrows(CelValidationException.class,
                () -> CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                        spdx_expr_allows("(MIT", ["MIT"])
                        """, CacheMode.NO_CACHE));
        assertThat(exception.getErrors()).anySatisfy(error ->
                assertThat(error.getMessage()).contains("Invalid SPDX expression: Unexpected end of expression"));
    }

    @Test
    void shouldAcceptValidSpdxExpressionLiterals() {
        assertDoesNotThrow(() -> CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile("""
                spdx_expr_allows(component.license_expression, ["MIT", "Apache-2.0"])
                    && spdx_expr_requires_any(component.license_expression, ["GPL-3.0-only"])
                """, CacheMode.NO_CACHE));
    }

}
