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

import alpine.common.logging.Logger;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParser;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpressionOperation;
import org.dependencytrack.parser.spdx.expression.model.SpdxOperator;
import org.dependencytrack.persistence.QueryManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Evaluates if a components resolved license is in the license group defined by the policy.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class LicenseGroupPolicyEvaluator extends AbstractPolicyEvaluator {

    /**
     * A license group that does not exist in the database and is therefore verified based on its
     * licenses list directly instad of a database check
     */
    private static class TemporaryLicenseGroup extends LicenseGroup {
        private static final long serialVersionUID = -1268650463377651000L;
    }

    /**
     * Whether a condition provides a positive list or negative list of licenses.
     * 
     * <p>
     * Configuring a LicenseGroupPolicy allows the user to specify conditions as either "IS
     * MyLicenseGroup" or "IS_NOT MyLicenseGroup", and a policy violation is reported when the
     * condition is met. The IS and IS_NOT is not very intuitive when actually evaluating a
     * condition; what it actually means is that either "IS_NOT" is selected, and the user provides
     * a list of licenses that are allowed to be used (violation if license is not in license
     * group), or "IS" is selected and the user provides a list of licenses that cannot be used
     * (violation if license is in license group).
     * 
     * <p>
     * In order to simplify thinking about license violations, this license group type is used.
     *
     */
    private static enum LicenseGroupType {
        /**
         * License group represents a list of licenses that are explicitly allowed to be used
         */
        AllowedLicenseList,
        /**
         * License group represents a list of licenses that are not allowed to be used
         */
        ForbiddenLicenseList;
    }

    private static final Logger LOGGER = Logger.getLogger(LicenseGroupPolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.LICENSE_GROUP;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();

        final List<PolicyCondition> policyConditions = super.extractSupportedConditions(policy);
        if (policyConditions.isEmpty()) {
            return violations;
        }

        final SpdxExpression expression = getSpdxExpressionFromComponent(component);

        for (final PolicyCondition condition : policyConditions) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition ("
                    + condition.getUuid() + ")");
            final LicenseGroup lg = qm.getObjectByUuid(LicenseGroup.class, condition.getValue());
            if (lg == null) {
                LOGGER.warn("The license group %s does not exist; Skipping evaluation of condition %s of policy %s"
                        .formatted(condition.getValue(), condition.getUuid(), policy.getName()));
                continue;
            }
            evaluateCondition(qm, condition, expression, lg, component, violations);
        }
        return violations;
    }

    /**
     * Retrieves the appropriate spdx expression from a component. If the component has a single
     * license, return spdx expression for that. If the component has an expression string as
     * license, parse it and return that.
     * 
     * @param component
     *            the component to retrieve the license expression for
     * @return parsed license expression
     */
    static SpdxExpression getSpdxExpressionFromComponent(final Component component) {
        SpdxExpression expression = null;

        final License license = component.getResolvedLicense();
        if (license != null) {
            expression = new SpdxExpression(license.getLicenseId());
        } else {
            String licenseString = component.getLicenseExpression();
            if (licenseString != null) {
                expression = new SpdxExpressionParser().parse(licenseString);
            } else if (component.getLicense() != null) {
                expression = new SpdxExpression(component.getLicense());
            } else {
                expression = new SpdxExpression("unresolved");
            }
        }

        return expression;
    }

    static LicenseGroup getTemporaryLicenseGroupForLicense(final License license) {
        LicenseGroup temporaryLicenseGroup = new TemporaryLicenseGroup();
        temporaryLicenseGroup.setLicenses(Collections.singletonList(license));
        return temporaryLicenseGroup;
    }

    /**
     * Evaluate policy condition for spdx expression and license group, and add violations to the
     * violations array.
     * 
     * @param qm
     *            The query manager to use for database queries
     * @param condition
     *            The condition to evaluate
     * @param expression
     *            the spdx expression to be checked for incompatibility with the license group
     * @param lg
     *            the license group to check for incompatibility. If this is null, interpret as
     *            "unresolved"
     * @param component
     *            the component for which policies are being checked
     * @param violations
     *            the list of violations, will be appended to in case of new violation
     * @return true if violations have been added to the list
     */
    static boolean evaluateCondition(final QueryManager qm, final PolicyCondition condition,
            final SpdxExpression expression, final LicenseGroup lg, final Component component,
            final List<PolicyConditionViolation> violations) {

        boolean hasViolations = false;
        if (condition.getOperator() == PolicyCondition.Operator.IS) {
            // report a violation if a license IS in the license group;
            // so check whether the expression is compatible given the provided list of forbidden licenses
            if (!canLicenseBeUsed(qm, expression, LicenseGroupType.ForbiddenLicenseList, lg)) {
                violations.add(new PolicyConditionViolation(condition, component));
                hasViolations = true;
            }
        }
        if (condition.getOperator() == PolicyCondition.Operator.IS_NOT) {
            // report a violation if a license IS_NOT in the license group;
            // so check whether the expression is compatible given the provided list of allowed licenses
            if (!canLicenseBeUsed(qm, expression, LicenseGroupType.AllowedLicenseList, lg)) {
                violations.add(new PolicyConditionViolation(condition, component));
                hasViolations = true;
            }
        }

        return hasViolations;
    }

    /**
     * Check spdx expression for compatibility with license group, where the license group is either
     * a list of allowed or forbidden licenses (positive or negative list). If the expression is an
     * SPDX operator, this function calls itself recursively to determine compatibility of the
     * expression's parts.
     * 
     * @param qm
     *            The query manager to use for database queries
     * @param expr
     *            the spdx expression to be checked for compatibility with the license group
     * @param groupType
     *            whether the given license group is a list of allowed or forbidden licenses
     * @param lg
     *            the license group to check for compatibility. If this is null, interpret as
     *            "unresolved".
     * @return whether the license expression is compatible with the license group under the
     *         condition
     */
    protected static boolean canLicenseBeUsed(final QueryManager qm, final SpdxExpression expr,
            final LicenseGroupType groupType, final LicenseGroup lg) {
        if (expr.getSpdxLicenseId() != null) {
            License license = qm.getLicense(expr.getSpdxLicenseId());
            if (groupType == LicenseGroupType.ForbiddenLicenseList) {
                if (license == null && lg != null) {
                    // unresolved license, and forbidden list given. This is ok
                    return true;
                }
                if (license != null && lg == null) {
                    // license resolved, but only unresolved forbidden. ok
                    return true;
                }
                if (license == null && lg == null) {
                    // license unresolved and unresolved is forbidden
                    return false;
                }
                // license resolved and negative list given
                return !doesLicenseGroupContainLicense(qm, lg, license);
            } else if (groupType == LicenseGroupType.AllowedLicenseList) {
                if (license == null && lg != null) {
                    // unresolved license, but list of allowed licenses given
                    return false;
                }
                if (license != null && lg == null) {
                    // license resolved, but only unresolved allowed
                    return false;
                }
                if (license == null && lg == null) {
                    // license unresolved and unresolved is allowed
                    return true;
                }
                // license resolved and positive list given
                return doesLicenseGroupContainLicense(qm, lg, license);
            } else {
                // should be unreachable
                return true;
            }
        }
        // check according to operation
        SpdxExpressionOperation operation = expr.getOperation();
        if (operation.getOperator() == SpdxOperator.OR) {
            // any of the OR operator's arguments needs to be compatible
            return operation.getArguments().stream().anyMatch(arg -> canLicenseBeUsed(qm, arg, groupType, lg));
        }
        if (operation.getOperator() == SpdxOperator.AND) {
            // all of the AND operator's arguments needs to be compatible
            return operation.getArguments().stream().allMatch(arg -> canLicenseBeUsed(qm, arg, groupType, lg));
        }
        if (operation.getOperator() == SpdxOperator.WITH) {
            // Transform `GPL-2.0 WITH classpath-exception` to `GPL-2.0-with-classpath-exception`
            String licenseName = operation.getArguments().get(0) + "-with-" + operation.getArguments().get(1);
            SpdxExpression license = new SpdxExpression(licenseName);
            return canLicenseBeUsed(qm, license, groupType, lg);
        }
        if (operation.getOperator() == SpdxOperator.PLUS) {
            // Transform `GPL-2.0+` to `GPL-2.0 OR GPL-2.0-or-later`
            SpdxExpression arg = operation.getArguments().get(0);
            return canLicenseBeUsed(qm, arg, groupType, lg)
                    || canLicenseBeUsed(qm, new SpdxExpression(expr.getSpdxLicenseId() + "-or-later"), groupType, lg);
        }
        // should be unreachable
        return true;
    }
    
    /**
     * Check if the license is contained in the license group. If this is a temporary license group,
     * don't ask the database but verify directly via the license's uuid
     * 
     * @param qm
     *            The query manager to use for database queries
     * @param lg
     *            The license group to check
     * @param license
     *            The license to check
     * @return Whether the license group contains the license
     */
    protected static boolean doesLicenseGroupContainLicense(final QueryManager qm, final LicenseGroup lg,
            final License license) {
        if (lg instanceof TemporaryLicenseGroup) {
            // this group was created just for this license check. Check its contents directly without the QueryManager.
            return lg.getLicenses().stream().anyMatch(groupLicense -> groupLicense.getUuid().equals(license.getUuid()));
        } else {
            return qm.doesLicenseGroupContainLicense(lg, license);
        }
    }

}
