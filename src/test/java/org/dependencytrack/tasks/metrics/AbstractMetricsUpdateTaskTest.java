package org.dependencytrack.tasks.metrics;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;

import java.util.Date;
import java.util.UUID;

abstract class AbstractMetricsUpdateTaskTest extends PersistenceCapableTest {

    protected PolicyViolation createPolicyViolation(final Component component, final Policy.ViolationState violationState, final PolicyViolation.Type type) {
        final var policy = qm.createPolicy(UUID.randomUUID().toString(), Policy.Operator.ALL, violationState);
        final var policyCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "");
        final var policyViolation = new PolicyViolation();

        policyViolation.setComponent(component);
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setTimestamp(new Date());
        policyViolation.setType(type);
        return qm.addPolicyViolationIfNotExist(policyViolation);
    }

}
