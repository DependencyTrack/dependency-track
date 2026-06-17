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

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class SeverityCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
            return """
                    vulns.exists(vuln, vuln.severity == "%s")
                    """.formatted(escapeQuotes(policyCondition.getValue()));
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
            return """
                    vulns.exists(vuln, vuln.severity != "%s")
                    """.formatted(escapeQuotes(policyCondition.getValue()));
        }

        return null;
    }

}
