package org.dependencytrack.policy;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Vulnerability;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class AttributedOnPolicyEvaluatorTest extends PersistenceCapableTest {

    @Parameterized.Parameters(name = "[{index}] attributedDate={0} operator={1} ageValue={2} shouldViolate={3}")
    public static Collection<?> testParameters() {
        return Arrays.asList(new Object[][]{
                // Test cases: [daysAgo, operator, periodValue, shouldViolate]

                // GREATER_THAN tests - violation when age > specified period
                {40, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P30D", true},   // 40 days > 30 days
                {20, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P30D", false},  // 20 days < 30 days
                {30, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P30D", false},  // 30 days = 30 days

                // GREATER_THAN_OR_EQUAL tests - violation when age >= specified period
                {40, PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P30D", true},  // 40 days >= 30 days
                {30, PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P30D", true},  // 30 days >= 30 days
                {20, PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P30D", false}, // 20 days < 30 days

                // EQUAL tests - violation when age = specified period
                {30, PolicyCondition.Operator.NUMERIC_EQUAL, "P30D", true},   // 30 days = 30 days
                {40, PolicyCondition.Operator.NUMERIC_EQUAL, "P30D", false},  // 40 days ≠ 30 days
                {20, PolicyCondition.Operator.NUMERIC_EQUAL, "P30D", false},  // 20 days ≠ 30 days

                // NOT_EQUAL tests - violation when age ≠ specified period
                {40, PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "P30D", true},  // 40 days ≠ 30 days
                {20, PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "P30D", true},  // 20 days ≠ 30 days
                {30, PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "P30D", false}, // 30 days = 30 days

                // LESS_THAN_OR_EQUAL tests - violation when age <= specified period
                {20, PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P30D", true},  // 20 days <= 30 days
                {30, PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P30D", true},  // 30 days <= 30 days
                {40, PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P30D", false}, // 40 days > 30 days

                // LESS_THAN tests - violation when age < specified period
                {20, PolicyCondition.Operator.NUMERIC_LESS_THAN, "P30D", true},  // 20 days < 30 days
                {30, PolicyCondition.Operator.NUMERIC_LESS_THAN, "P30D", false}, // 30 days = 30 days
                {40, PolicyCondition.Operator.NUMERIC_LESS_THAN, "P30D", false}, // 40 days > 30 days

                // Different period formats
                {40, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P1M", true},   // ~40 days > 1 month
                {25, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P1M", false},  // ~25 days < 1 month
                {8, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P1W", true},   // 8 days > 1 week
                {6, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P1W", false},  // 6 days < 1 week

                // Edge cases
                {1, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P1D", false},  // 1 day = 1 day
                {2, PolicyCondition.Operator.NUMERIC_GREATER_THAN, "P1D", true},   // 2 days > 1 day
        });
    }

    @Parameterized.Parameter()
    public int daysAgo;

    @Parameterized.Parameter(1)
    public PolicyCondition.Operator operator;

    @Parameterized.Parameter(2)
    public String ageValue;

    @Parameterized.Parameter(3)
    public boolean shouldViolate;

    private AttributedOnPolicyEvaluator evaluator;
    private Component component;
    private Policy policy;
    private PolicyCondition condition;
    private Vulnerability vulnerability;
    private FindingAttribution attribution;

    @Before
    public void setUp() {
        evaluator = new AttributedOnPolicyEvaluator();

        // Create test entities
        component = new Component();
        component.setName("test-component");
        component.setVersion("1.0.0");

        vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2023-1234");

        policy = new Policy();
        policy.setName("test-policy");

        condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.ATTRIBUTED_ON);
        condition.setOperator(operator);
        condition.setValue(ageValue);

        attribution = new FindingAttribution();
        Date attributedDate = Date.from(LocalDate.now().minusDays(daysAgo)
                .atStartOfDay(ZoneId.systemDefault()).toInstant());
        attribution.setAttributedOn(attributedDate);

        // Mock the query manager
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);
    }

    @Test
    public void testAgeBasedPolicyEvaluation() {
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
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.emptyList());
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNoFindingAttribution() {
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(null);
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNullAttributedOnDate() {
        attribution.setAttributedOn(null);
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);
        policy.setPolicyConditions(Collections.singletonList(condition));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testInvalidPeriodFormat() {
        condition.setValue("INVALID_PERIOD");
        policy.setPolicyConditions(Collections.singletonList(condition));
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testZeroPeriod() {
        condition.setValue("P0D");
        policy.setPolicyConditions(Collections.singletonList(condition));
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNegativePeriod() {
        condition.setValue("P-30D");
        policy.setPolicyConditions(Collections.singletonList(condition));
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testUnsupportedOperator() {
        condition.setOperator(PolicyCondition.Operator.valueOf("CONTAINS"));
        policy.setPolicyConditions(Collections.singletonList(condition));
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testMultipleVulnerabilities() {
        // Create additional vulnerabilities with different attribution dates
        Vulnerability vuln2 = new Vulnerability();
        vuln2.setVulnId("CVE-2023-5678");

        FindingAttribution attr2 = new FindingAttribution();
        Date oldDate = Date.from(LocalDate.now().minusDays(60)
                .atStartOfDay(ZoneId.systemDefault()).toInstant());
        attr2.setAttributedOn(oldDate);

        condition.setOperator(PolicyCondition.Operator.NUMERIC_GREATER_THAN);
        condition.setValue("P30D");
        policy.setPolicyConditions(Collections.singletonList(condition));

        when(qm.getAllVulnerabilities(component)).thenReturn(Arrays.asList(vulnerability, vuln2));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);
        when(qm.getFindingAttribution(vuln2, component)).thenReturn(attr2);

        // Set first vulnerability to 20 days ago (no violation) and second to 60 days ago (violation)
        Date recentDate = Date.from(LocalDate.now().minusDays(20)
                .atStartOfDay(ZoneId.systemDefault()).toInstant());
        attribution.setAttributedOn(recentDate);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).hasSize(1); // Only the 60-day-old vulnerability should violate
    }

    @Test
    public void testSupportedSubject() {
        assertThat(evaluator.supportedSubject()).isEqualTo(PolicyCondition.Subject.ATTRIBUTED_ON);
    }

    @Test
    public void testEmptyPolicyConditions() {
        policy.setPolicyConditions(Collections.emptyList());
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testNullPolicyConditionValue() {
        condition.setValue(null);
        policy.setPolicyConditions(Collections.singletonList(condition));
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }

    @Test
    public void testEmptyPolicyConditionValue() {
        condition.setValue("   ");
        policy.setPolicyConditions(Collections.singletonList(condition));
        when(qm.getAllVulnerabilities(component)).thenReturn(Collections.singletonList(vulnerability));
        when(qm.getFindingAttribution(vulnerability, component)).thenReturn(attribution);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        assertThat(violations).isEmpty();
    }
}