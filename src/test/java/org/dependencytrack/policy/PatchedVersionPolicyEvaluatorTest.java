package org.dependencytrack.policy;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Vulnerability;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class PatchedVersionPolicyEvaluatorTest extends PersistenceCapableTest {

    @Parameterized.Parameters(name = "[{index}] patchedVersions={0} operator={1} conditionValue={2} shouldViolate={3}")
    public static Collection<?> testParameters() {
        return Arrays.asList(new Object[][]{
                // Test cases: [patchedVersions, operator, conditionValue, shouldViolate]

                // IS operator with "true" condition value
                {"1.2.3", PolicyCondition.Operator.IS, "true", true},      // has patched version, expects true -> violates
                {null, PolicyCondition.Operator.IS, "true", false},        // no patched version, expects true -> no violation
                {"", PolicyCondition.Operator.IS, "true", false},          // empty patched version, expects true -> no violation
                {"   ", PolicyCondition.Operator.IS, "true", false},       // whitespace only, expects true -> no violation

                // IS operator with "false" condition value
                {"1.2.3", PolicyCondition.Operator.IS, "false", false},    // has patched version, expects false -> no violation
                {null, PolicyCondition.Operator.IS, "false", true},        // no patched version, expects false -> violates
                {"", PolicyCondition.Operator.IS, "false", true},          // empty patched version, expects false -> violates
                {"   ", PolicyCondition.Operator.IS, "false", true},       // whitespace only, expects false -> violates

                // IS_NOT operator with "true" condition value
                {"1.2.3", PolicyCondition.Operator.IS_NOT, "true", false}, // has patched version, expects not true -> no violation
                {null, PolicyCondition.Operator.IS_NOT, "true", true},     // no patched version, expects not true -> violates
                {"", PolicyCondition.Operator.IS_NOT, "true", true},       // empty patched version, expects not true -> violates
                {"   ", PolicyCondition.Operator.IS_NOT, "true", true},    // whitespace only, expects not true -> violates

                // IS_NOT operator with "false" condition value
                {"1.2.3", PolicyCondition.Operator.IS_NOT, "false", true}, // has patched version, expects not false -> violates
                {null, PolicyCondition.Operator.IS_NOT, "false", false},   // no patched version, expects not false -> no violation
                {"", PolicyCondition.Operator.IS_NOT, "false", false},     // empty patched version, expects not false -> no violation
                {"   ", PolicyCondition.Operator.IS_NOT, "false", false},  // whitespace only, expects not false -> no violation

                // Case-insensitive tests
                {"1.2.3", PolicyCondition.Operator.IS, "TRUE", true},      // uppercase true
                {"1.2.3", PolicyCondition.Operator.IS, "True", true},      // mixed case true
                {"1.2.3", PolicyCondition.Operator.IS, "FALSE", false},    // uppercase false
                {"1.2.3", PolicyCondition.Operator.IS, "False", false},    // mixed case false

                // Multiple version formats
                {"v1.2.3, v1.2.4", PolicyCondition.Operator.IS, "true", true},    // multiple versions
                {">=1.2.3", PolicyCondition.Operator.IS, "true", true},           // version range
                {"1.2.3-patch1", PolicyCondition.Operator.IS, "true", true},      // version with suffix
        });
    }

    @Parameterized.Parameter()
    public String patchedVersions;

    @Parameterized.Parameter(1)
    public PolicyCondition.Operator operator;

    @Parameterized.Parameter(2)
    public String conditionValue;

    @Parameterized.Parameter(3)
    public boolean shouldViolate;

    private PatchedVersionPolicyEvaluator evaluator;
    private Component component;
    private Policy policy;
    private PolicyCondition condition;
    private Vulnerability vulnerability;

    @Before
    public void setUp() {
        evaluator = new PatchedVersionPolicyEvaluator();

        // Create test entities
        component = new Component();
        component.setName("test-component");
        component.setVersion("1.0.0");

        vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2023-1234");
        vulnerability.setPatchedVersions(patchedVersions);

        policy = new Policy();
        policy.setName("test-policy");

        condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.PATCH_VERSION);
        condition.setOperator(operator);
        condition.setValue(conditionValue);

        // Mock the query manager
        when(qm.getAllVulnerabilities(component, false)).thenReturn(Collections.singletonList(vulnerability));
    }

    @Test
    public void testPatchedVersionPolicyEvaluation() {
        // Arrange
        policy.setPolicyConditions(Collections.singletonList(condition));

        // Act
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);

        // Assert
        if (shouldViolate) {
            assertThat(violations)
                    .hasSize(1)
                    .extracting(PolicyConditionViolation::getPolicyCondition)
                    .containsExactly(condition);
        } else {
            assertThat(violations).isEmpty();
        }
    }

    // Additional non-parameterized tests

    @Test
    public void testNullPolicy() {
        List<PolicyConditionViolation> violations = evaluator.evaluate(null, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNullComponent() {
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, null);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNoVulnerabilities() {
        when(qm.getAllVulnerabilities(component, false)).thenReturn(Collections.emptyList());
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testInvalidConditionValue() {
        condition.setValue("invalid");
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNullConditionValue() {
        condition.setValue(null);
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testEmptyConditionValue() {
        condition.setValue("");
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testWhitespaceConditionValue() {
        condition.setValue("   ");
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testUnsupportedOperator() {
        condition.setOperator(PolicyCondition.Operator.NUMERIC_GREATER_THAN);
        condition.setValue("true");
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testMultipleVulnerabilities() {
        // Create additional vulnerability with different patched version status
        Vulnerability vuln2 = new Vulnerability();
        vuln2.setVulnId("CVE-2023-5678");
        vuln2.setPatchedVersions(null); // No patched version

        // Set up condition to detect vulnerabilities without patched versions
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("false");
        policy.setPolicyConditions(Collections.singletonList(condition));

        // First vulnerability has patched versions, second doesn't
        vulnerability.setPatchedVersions("1.2.3");

        when(qm.getAllVulnerabilities(component, false)).thenReturn(Arrays.asList(vulnerability, vuln2));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).hasSize(1); // Only the vulnerability without patched versions should violate
    }

    @Test
    public void testMultiplePolicyConditions() {
        // Create two conditions
        PolicyCondition condition1 = new PolicyCondition();
        condition1.setSubject(PolicyCondition.Subject.PATCH_VERSION);
        condition1.setOperator(PolicyCondition.Operator.IS);
        condition1.setValue("true");

        PolicyCondition condition2 = new PolicyCondition();
        condition2.setSubject(PolicyCondition.Subject.PATCH_VERSION);
        condition2.setOperator(PolicyCondition.Operator.IS_NOT);
        condition2.setValue("false");

        policy.setPolicyConditions(Arrays.asList(condition1, condition2));

        // Vulnerability with patched versions should violate both conditions
        vulnerability.setPatchedVersions("1.2.3");

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).hasSize(2);
    }

    @Test
    public void testMixedSubjectConditions() {
        // Create condition with different subject that should be ignored
        PolicyCondition irrelevantCondition = new PolicyCondition();
        irrelevantCondition.setSubject(PolicyCondition.Subject.COMPONENT_HASH);
        irrelevantCondition.setOperator(PolicyCondition.Operator.IS);
        irrelevantCondition.setValue("1.0.0");

        PolicyCondition relevantCondition = new PolicyCondition();
        relevantCondition.setSubject(PolicyCondition.Subject.PATCH_VERSION);
        relevantCondition.setOperator(PolicyCondition.Operator.IS);
        relevantCondition.setValue("true");

        policy.setPolicyConditions(Arrays.asList(irrelevantCondition, relevantCondition));

        vulnerability.setPatchedVersions("1.2.3");

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).hasSize(1); // Only the PATCH_VERSION condition should be evaluated
        assertThat(violations.get(0).getPolicyCondition()).isEqualTo(relevantCondition);
    }

    @Test
    public void testSupportedSubject() {
        assertThat(evaluator.supportedSubject()).isEqualTo(PolicyCondition.Subject.PATCH_VERSION);
    }

    @Test
    public void testEmptyPolicyConditions() {
        policy.setPolicyConditions(Collections.emptyList());
        when(qm.getAllVulnerabilities(component, false)).thenReturn(Collections.singletonList(vulnerability));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNullPolicyConditions() {
        policy.setPolicyConditions(null);
        when(qm.getAllVulnerabilities(component, false)).thenReturn(Collections.singletonList(vulnerability));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNumericStringValues() {
        // Test various non-boolean values that should be ignored
        String[] invalidValues = {"0", "1", "123", "0.5", "-1"};

        for (String invalidValue : invalidValues) {
            condition.setValue(invalidValue);
            condition.setOperator(PolicyCondition.Operator.IS);
            policy.setPolicyConditions(Collections.singletonList(condition));

            List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
            assertThat(violations).isEmpty();
        }
    }

    @Test
    public void testBooleanLikeStrings() {
        // Test strings that might be confused for booleans
        String[] almostBooleanValues = {"truee", "falsee", "True ", " false", "yes", "no", "1", "0"};

        for (String value : almostBooleanValues) {
            condition.setValue(value);
            condition.setOperator(PolicyCondition.Operator.IS);
            policy.setPolicyConditions(Collections.singletonList(condition));

            List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
            assertThat(violations).isEmpty();
        }
    }
}