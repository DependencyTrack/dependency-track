package org.dependencytrack.tasks;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyEvaluationTaskTest extends PersistenceCapableTest {

    @Test
    public void testPolicyEvaluationForSingleComponent() {
        Project project = new Project();
        project.setName("my-project");
        project.setGroup("com.example");
        project.setVersion("1.0.0");
        qm.createProject(project, Collections.emptyList(), false);

        Component component = new Component();
        component.setGroup("com.example");
        component.setName("my-component");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/my-component@1.0.0");
        component.setProject(project);
        qm.createComponent(component, false);

        // a policy that identifies the upper component and thus should be violated
        Policy policy = qm.createPolicy("my-policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "pkg:maven/com.example/my-component@1.0.0");

        PolicyEvaluationTask task = new PolicyEvaluationTask();
        task.inform(new PolicyEvaluationEvent(component).project(project));

        PaginatedResult policyViolations = qm.getPolicyViolations(project, false);
        assertThat(policyViolations.getTotal()).isEqualTo(1);
    }

}
