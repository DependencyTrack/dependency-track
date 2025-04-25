package org.dependencytrack.policy;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class VersionPolicyEvaluatorTest extends PersistenceCapableTest {

    private VersionPolicyEvaluator evaluator;

    @BeforeEach
    public void setUp() {
        evaluator = new VersionPolicyEvaluator();
        evaluator.setQueryManager(qm);
    }

    @Test
    void testLessThanOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_LESS_THAN, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void testLessThanOrEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void testEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void testNotEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void testGreaterThanOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void testGreaterThanOrEqualOperator() {
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "1.1.1");

        final var component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

}