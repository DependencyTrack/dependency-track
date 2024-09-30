package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import alpine.server.filters.AuthorizationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.Operator;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import javax.jdo.JDOObjectNotFoundException;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.hamcrest.CoreMatchers.equalTo;

public class PolicyConditionResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(PolicyConditionResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(AuthorizationFilter.class));

    @Test
    public void testCreateCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Operator.ANY);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final Response response = jersey.target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "subject": "PACKAGE_URL",
                          "operator": "MATCHES",
                          "value": "pkg:maven/foo/bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "uuid": "${json-unit.any-string}",
                  "subject": "PACKAGE_URL",
                  "operator": "MATCHES",
                  "value": "pkg:maven/foo/bar"
                }
                """);
    }

    @Test
    public void testCreateConditionWhenPolicyDoesNotExist() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey.target("%s/cec42e01-62a7-4c86-9b8f-cd6650be2888/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "subject": "PACKAGE_URL",
                          "operator": "MATCHES",
                          "value": "pkg:maven/foo/bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the policy could not be found.");
    }

    @Test
    public void testCreateConditionWhenUnauthorized() {
        final Response response = jersey.target("%s/cec42e01-62a7-4c86-9b8f-cd6650be2888/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "subject": "PACKAGE_URL",
                          "operator": "MATCHES",
                          "value": "pkg:maven/foo/bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void testUpdateCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Operator.ANY);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final var condition = new PolicyCondition();
        condition.setPolicy(policy);
        condition.setSubject(PolicyCondition.Subject.PACKAGE_URL);
        condition.setOperator(PolicyCondition.Operator.MATCHES);
        condition.setValue("pkg:maven/foo/bar");
        qm.persist(condition);

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """.formatted(condition.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("conditionUuid", equalTo(condition.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.matches:conditionUuid}",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """);
    }

    @Test
    public void testUpdateConditionWhenConditionDoesNotExist() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "8683b1db-96a3-4014-baf8-03e8cab8c647",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the policy condition could not be found.");
    }

    @Test
    public void testUpdateConditionWhenUnauthorized() {
        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "8683b1db-96a3-4014-baf8-03e8cab8c647",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void testDeleteCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Operator.ANY);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final var condition = new PolicyCondition();
        condition.setPolicy(policy);
        condition.setSubject(PolicyCondition.Subject.PACKAGE_URL);
        condition.setOperator(PolicyCondition.Operator.MATCHES);
        condition.setValue("pkg:maven/foo/bar");
        qm.persist(condition);

        final Response response = jersey.target("%s/condition/%s".formatted(V1_POLICY, condition.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(PolicyCondition.class, condition.getId()));
    }

    @Test
    public void testDeleteConditionWhenConditionDoesNotExist() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey.target("%s/condition/%s".formatted(V1_POLICY, UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the policy condition could not be found.");
    }

    @Test
    public void testDeleteConditionWhenUnauthorized() {
        final Response response = jersey.target("%s/condition/%s".formatted(V1_POLICY, UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(403);
    }

}