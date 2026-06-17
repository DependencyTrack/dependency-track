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

import com.google.protobuf.Descriptors.Descriptor;
import dev.cel.common.CelVarDecl;
import dev.cel.compiler.CelCompiler;
import dev.cel.compiler.CelCompilerFactory;
import dev.cel.extensions.CelExtensions;
import dev.cel.parser.CelStandardMacro;
import dev.cel.runtime.CelRuntime;
import dev.cel.runtime.CelRuntimeFactory;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Tools;
import org.dependencytrack.proto.policy.v1.VersionDistance;
import org.dependencytrack.proto.policy.v1.Vulnerability;

public enum CelPolicyType {

    COMPONENT(
            CelPolicyVariable.COMPONENT,
            CelPolicyVariable.PROJECT,
            CelPolicyVariable.VULNS,
            CelPolicyVariable.NOW),
    VULNERABILITY(
            CelPolicyVariable.COMPONENT,
            CelPolicyVariable.PROJECT,
            CelPolicyVariable.VULN,
            CelPolicyVariable.NOW);

    private final CelCompiler compiler;
    private final CelRuntime runtime;

    CelPolicyType(CelPolicyVariable... variables) {
        final var library = new CelPolicyLibrary();

        // NB: Message types must be registered directly on the builders,
        // not inside CelRuntimeLibrary#setRuntimeOptions, because the runtime's build()
        // creates the descriptor pool before invoking library callbacks.
        final var compilerBuilder = CelCompilerFactory
                .standardCelCompilerBuilder()
                .setStandardMacros(CelStandardMacro.STANDARD_MACROS)
                .addLibraries(CelExtensions.strings(), library)
                .addMessageTypes(messageTypes());
        for (final CelPolicyVariable variable : variables) {
            compilerBuilder.addVarDeclarations(
                    CelVarDecl.newVarDeclaration(
                            variable.variableName(),
                            variable.celType()));
        }
        this.compiler = compilerBuilder.build();

        this.runtime = CelRuntimeFactory
                .standardCelRuntimeBuilder()
                .addLibraries(CelExtensions.strings(), library)
                .addMessageTypes(messageTypes())
                .build();
    }

    private static Descriptor[] messageTypes() {
        return new Descriptor[]{
                Component.getDescriptor(),
                Component.Property.getDescriptor(),
                License.getDescriptor(),
                License.Group.getDescriptor(),
                Project.getDescriptor(),
                Project.Metadata.getDescriptor(),
                Project.Property.getDescriptor(),
                Tools.getDescriptor(),
                Vulnerability.getDescriptor(),
                Vulnerability.Alias.getDescriptor(),
                VersionDistance.getDescriptor(),
        };
    }

    CelCompiler compiler() {
        return compiler;
    }

    CelRuntime runtime() {
        return runtime;
    }

}
