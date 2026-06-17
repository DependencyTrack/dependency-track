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
package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.parser.common.resolver.CweResolver;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class CweCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final List<Integer> conditionCwes = Arrays.stream(policyCondition.getValue().split(","))
                .map(String::trim)
                .map(CweResolver.getInstance()::parseCweString)
                .filter(Objects::nonNull)
                .sorted()
                .toList();
        if (conditionCwes.isEmpty()) {
            return null;
        }

        final String celCweListLiteral = "[%s]".formatted(conditionCwes.stream()
                .map(String::valueOf)
                .collect(Collectors.joining(", ")));

        if (policyCondition.getOperator() == PolicyCondition.Operator.CONTAINS_ANY) {
            // ANY of the vulnerabilities affecting the component have ANY of the
            // CWEs defined in the policy condition assigned to them.
            return """
                    %s.exists(policyCwe,
                        vulns.exists(vuln,
                            vuln.cwes.exists(vulnCwe, vulnCwe == policyCwe)
                        )
                    )
                    """.formatted(celCweListLiteral);
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.CONTAINS_ALL) {
            // ANY of the vulnerabilities affecting the component have ALL the
            // CWEs defined in the policy condition assigned to them.
            return """
                    vulns.exists(vuln,
                        %s.all(policyCwe,
                            vuln.cwes.exists(vulnCwe, vulnCwe == policyCwe)
                        )
                    )
                    """.formatted(celCweListLiteral);
        }

        return null;
    }

}
