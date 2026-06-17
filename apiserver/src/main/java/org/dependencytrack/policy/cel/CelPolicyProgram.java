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
import dev.cel.runtime.CelEvaluationException;
import dev.cel.runtime.CelRuntime;
import org.apache.commons.collections4.MultiValuedMap;

import java.util.Map;

import static org.apache.commons.collections4.MultiMapUtils.unmodifiableMultiValuedMap;

public final class CelPolicyProgram {

    private final CelRuntime.Program program;
    private final MultiValuedMap<CelType, String> requirements;

    CelPolicyProgram(final CelRuntime.Program program, final MultiValuedMap<CelType, String> requirements) {
        this.program = program;
        this.requirements = unmodifiableMultiValuedMap(requirements);
    }

    MultiValuedMap<CelType, String> getRequirements() {
        return requirements;
    }

    boolean execute(final Map<String, Object> arguments) throws CelEvaluationException {
        return (Boolean) program.eval(arguments);
    }

}
