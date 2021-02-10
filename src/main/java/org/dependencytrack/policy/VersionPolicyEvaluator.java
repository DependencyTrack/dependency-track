package org.dependencytrack.policy;

import alpine.logging.Logger;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.util.ComponentVersion;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a components version against a policy.
 *
 * @since 4.2.0
 */
public class VersionPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(VersionPolicyEvaluator.class);

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.VERSION;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final var componentVersion = new ComponentVersion(component.getVersion());

        final List<PolicyConditionViolation> violations = new ArrayList<>();

        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");

            final var conditionVersion = new ComponentVersion(condition.getValue());
            if (conditionVersion.getVersionParts().isEmpty()) {
                LOGGER.warn("Unable to parse version (" + condition.getValue() + " provided by condition");
                continue;
            }

            if (matches(componentVersion, conditionVersion, condition.getOperator())) {
                violations.add(new PolicyConditionViolation(condition, component));
            }
        }

        return violations;
    }

    static boolean matches(final ComponentVersion componentVersion,
                           final ComponentVersion conditionVersion,
                           final PolicyCondition.Operator operator) {
        final int comparisonResult = componentVersion.compareTo(conditionVersion);
        switch (operator) {
            case NUMERIC_EQUAL:
                return comparisonResult == 0;
            case NUMERIC_NOT_EQUAL:
                return comparisonResult != 0;
            case NUMERIC_LESS_THAN:
                return comparisonResult < 0;
            case NUMERIC_LESSER_THAN_OR_EQUAL:
                return comparisonResult <= 0;
            case NUMERIC_GREATER_THAN:
                return comparisonResult > 0;
            case NUMERIC_GREATER_THAN_OR_EQUAL:
                return comparisonResult >= 0;
            default:
                LOGGER.warn("Unsupported operation " + operator);
                break;
        }
        return false;
    }

}
