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
package org.dependencytrack.policy;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;

import java.util.ArrayList;
import java.util.List;

public class LatestVersionPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final String STATE_LATEST   = "LATEST";
    private static final String STATE_OUTDATED = "OUTDATED";
    private static final String STATE_UNKNOWN  = "UNKNOWN";

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {

        final List<PolicyConditionViolation> violations = new ArrayList<>();

        for (final PolicyCondition condition : extractSupportedConditions(policy)) {

            final String expected = normalize(condition.getValue());

            RepositoryMetaComponent meta = component.getRepositoryMeta();

            if (meta == null && qm != null) {
                final PackageURL purl = component.getPurlCoordinates();
                if (purl != null) {
                    final RepositoryType repoType = toRepositoryType(purl.getType());
                    final String namespace = purl.getNamespace();
                    final String name = purl.getName();

                    if (repoType != null && name != null) {
                        meta = qm.getRepositoryMetaComponent(repoType, namespace, name);
                    }
                }
            }

            final String current = component.getVersion();
            final String latest  = (meta != null) ? meta.getLatestVersion() : null;

            final String actualState;
            if (meta == null || current == null || latest == null) {
                actualState = STATE_UNKNOWN;
            } else if (current.equals(latest)) {
                actualState = STATE_LATEST;
            } else {
                actualState = STATE_OUTDATED;
            }

            final boolean matches = actualState.equals(expected);

            if (condition.getOperator() == PolicyCondition.Operator.IS) {
                if (matches) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            } else if (condition.getOperator() == PolicyCondition.Operator.IS_NOT) {
                if (!matches) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            }
        }

        return violations;
    }

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.LATEST_VERSION_STATUS;
    }

    private static String normalize(final String v) {
        return v == null ? null : v.trim().toUpperCase();
    }

    private static RepositoryType toRepositoryType(final String purlType) {
        return RepositoryType.valueOf(purlType.trim().toUpperCase());
    }
}
