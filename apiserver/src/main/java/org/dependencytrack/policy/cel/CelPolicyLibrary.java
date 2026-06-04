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

import dev.cel.checker.CelCheckerBuilder;
import dev.cel.common.CelContainer;
import dev.cel.common.CelFunctionDecl;
import dev.cel.common.CelOverloadDecl;
import dev.cel.common.types.ListType;
import dev.cel.common.types.SimpleType;
import dev.cel.compiler.CelCompilerLibrary;
import dev.cel.runtime.CelFunctionBinding;
import dev.cel.runtime.CelRuntimeBuilder;
import dev.cel.runtime.CelRuntimeLibrary;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.VersionDistance;

import java.util.List;
import java.util.Set;

import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VERSION_DISTANCE;

final class CelPolicyLibrary implements CelCompilerLibrary, CelRuntimeLibrary {

    enum Function {
        DEPENDS_ON(
                CelFunctionDecl.newFunctionDeclaration(
                        "depends_on",
                        CelOverloadDecl.newMemberOverload(
                                "project_depends_on_component_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_PROJECT, TYPE_COMPONENT))),
                CelFunctionBinding.from(
                        "project_depends_on_component_bool",
                        Project.class,
                        Component.class,
                        CelPolicyFunctions::dependsOn)),
        IS_DEPENDENCY_OF(
                CelFunctionDecl.newFunctionDeclaration(
                        "is_dependency_of",
                        CelOverloadDecl.newMemberOverload(
                                "component_is_dependency_of_component_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT, TYPE_COMPONENT))),
                CelFunctionBinding.from(
                        "component_is_dependency_of_component_bool",
                        Component.class,
                        Component.class,
                        CelPolicyFunctions::isDependencyOf)),
        IS_EXCLUSIVE_DEPENDENCY_OF(
                CelFunctionDecl.newFunctionDeclaration(
                        "is_exclusive_dependency_of",
                        CelOverloadDecl.newMemberOverload(
                                "component_is_exclusive_dependency_of_component_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT, TYPE_COMPONENT))),
                CelFunctionBinding.from(
                        "component_is_exclusive_dependency_of_component_bool",
                        Component.class,
                        Component.class,
                        CelPolicyFunctions::isExclusiveDependencyOf)),
        IS_DIRECT_DEPENDENCY_OF(
                CelFunctionDecl.newFunctionDeclaration(
                        "is_direct_dependency_of",
                        CelOverloadDecl.newMemberOverload(
                                "component_is_direct_dependency_of_component_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT, TYPE_COMPONENT))),
                CelFunctionBinding.from(
                        "component_is_direct_dependency_of_component_bool",
                        Component.class,
                        Component.class,
                        CelPolicyFunctions::isDirectDependencyOf)),
        MATCHES_RANGE(
                CelFunctionDecl.newFunctionDeclaration(
                        "matches_range",
                        CelOverloadDecl.newMemberOverload(
                                "component_matches_range_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT, SimpleType.STRING)),
                        CelOverloadDecl.newMemberOverload(
                                "project_matches_range_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_PROJECT, SimpleType.STRING))),
                CelFunctionBinding.from(
                        "component_matches_range_bool",
                        Component.class,
                        String.class,
                        (component, range) -> CelPolicyFunctions.matchesRange(component.getVersion(), range)),
                CelFunctionBinding.from(
                        "project_matches_range_bool",
                        Project.class,
                        String.class,
                        (project, range) -> CelPolicyFunctions.matchesRange(project.getVersion(), range))),
        COMPARE_AGE(
                CelFunctionDecl.newFunctionDeclaration(
                        "compare_age",
                        CelOverloadDecl.newMemberOverload(
                                "compare_age_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT, SimpleType.STRING, SimpleType.STRING))),
                CelFunctionBinding.from(
                        "compare_age_bool",
                        List.of(Component.class, String.class, String.class),
                        args -> CelPolicyFunctions.isComponentOld((Component) args[0], (String) args[1], (String) args[2]))),
        VERSION_DISTANCE(
                CelFunctionDecl.newFunctionDeclaration(
                        "version_distance",
                        CelOverloadDecl.newMemberOverload(
                                "matches_version_distance_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT, SimpleType.STRING, TYPE_VERSION_DISTANCE))),
                CelFunctionBinding.from(
                        "matches_version_distance_bool",
                        List.of(Component.class, String.class, VersionDistance.class),
                        args -> CelPolicyFunctions.matchesVersionDistance((Component) args[0], (String) args[1], (VersionDistance) args[2]))),
        HAS_PACKAGE_ARTIFACT_HASH_MISMATCH(
                CelFunctionDecl.newFunctionDeclaration(
                        "has_package_artifact_hash_mismatch",
                        CelOverloadDecl.newMemberOverload(
                                "component_has_package_artifact_hash_mismatch_bool",
                                SimpleType.BOOL,
                                List.of(TYPE_COMPONENT))),
                CelFunctionBinding.from(
                        "component_has_package_artifact_hash_mismatch_bool",
                        List.of(Component.class),
                        args -> CelPolicyFunctions.hasPackageArtifactHashMismatch((Component) args[0]))),
        SPDX_EXPR_ALLOWS(
                CelFunctionDecl.newFunctionDeclaration(
                        "spdx_expr_allows",
                        CelOverloadDecl.newGlobalOverload(
                                "spdx_expr_allows_string_list_bool",
                                SimpleType.BOOL,
                                List.of(SimpleType.STRING, ListType.create(SimpleType.STRING)))),
                CelFunctionBinding.from(
                        "spdx_expr_allows_string_list_bool",
                        String.class,
                        List.class,
                        CelPolicyFunctions::spdxExprAllows)),
        SPDX_EXPR_REQUIRES_ANY(
                CelFunctionDecl.newFunctionDeclaration(
                        "spdx_expr_requires_any",
                        CelOverloadDecl.newGlobalOverload(
                                "spdx_expr_requires_any_string_list_bool",
                                SimpleType.BOOL,
                                List.of(SimpleType.STRING, ListType.create(SimpleType.STRING)))),
                CelFunctionBinding.from(
                        "spdx_expr_requires_any_string_list_bool",
                        String.class,
                        List.class,
                        CelPolicyFunctions::spdxExprRequiresAny));

        private final CelFunctionDecl functionDecl;
        private final Set<CelFunctionBinding> functionBindings;

        Function(CelFunctionDecl functionDecl, CelFunctionBinding... functionBindings) {
            this.functionDecl = functionDecl;
            this.functionBindings = Set.of(functionBindings);
        }

        String functionName() {
            return functionDecl.name();
        }
    }

    @Override
    public void setCheckerOptions(CelCheckerBuilder checkerBuilder) {
        checkerBuilder.setContainer(CelContainer.ofName("org.dependencytrack.policy"));
        for (final Function function : Function.values()) {
            checkerBuilder.addFunctionDeclarations(function.functionDecl);
        }
    }

    @Override
    public void setRuntimeOptions(CelRuntimeBuilder runtimeBuilder) {
        for (final Function function : Function.values()) {
            runtimeBuilder.addFunctionBindings(function.functionBindings);
        }
    }

}
