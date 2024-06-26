package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.resources.v1.exception.ConstraintViolationExceptionMapper;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED;
import static org.hamcrest.CoreMatchers.equalTo;

public class TagResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TagResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(ConstraintViolationExceptionMapper.class));

    @Test
    public void getTagsTest() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(projectA, List.of(tagFoo, tagBar));
        qm.bind(projectB, List.of(tagFoo));
        qm.bind(projectC, List.of(tagFoo));

        projectA.addAccessTeam(team);
        projectB.addAccessTeam(team);
        // NB: Not assigning projectC

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setTags(List.of(tagBar));
        qm.persist(policy);

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "bar",
                    "projectCount": 1,
                    "policyCount": 1
                  },
                  {
                    "name": "foo",
                    "projectCount": 2,
                    "policyCount": 0
                  }
                ]
                """);
    }

    @Test
    public void getTagsWithPaginationTest() {
        for (int i = 0; i < 5; i++) {
            qm.createTag("tag-" + (i + 1));
        }

        Response response = jersey.target(V1_TAG)
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "tag-1",
                    "projectCount": 0,
                    "policyCount": 0
                  },
                  {
                    "name": "tag-2",
                    "projectCount": 0,
                    "policyCount": 0
                  },
                  {
                    "name": "tag-3",
                    "projectCount": 0,
                    "policyCount": 0
                  }
                ]
                """);

        response = jersey.target(V1_TAG)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "tag-4",
                    "projectCount": 0,
                    "policyCount": 0
                  },
                  {
                    "name": "tag-5",
                    "projectCount": 0,
                    "policyCount": 0
                  }
                ]
                """);
    }

    @Test
    public void getTagsWithFilterTest() {
        qm.createTag("foo");
        qm.createTag("bar");

        final Response response = jersey.target(V1_TAG)
                .queryParam("filter", "O") // Should be case-insensitive.
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "foo",
                    "projectCount": 0,
                    "policyCount": 0
                  }
                ]
                """);
    }

    @Test
    public void getTagsSortByProjectCountTest() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(projectA, List.of(tagFoo, tagBar));
        qm.bind(projectB, List.of(tagFoo));

        final Response response = jersey.target(V1_TAG)
                .queryParam("sortName", "projectCount")
                .queryParam("sortOrder", "desc")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "name": "foo",
                    "projectCount": 2,
                    "policyCount": 0
                  },
                  {
                    "name": "bar",
                    "projectCount": 1,
                    "policyCount": 0
                  }
                ]
                """);
    }

    @Test
    public void getTaggedProjectsTest() {
        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        qm.bind(projectA, List.of(tagFoo, tagBar));
        qm.bind(projectB, List.of(tagFoo));
        qm.bind(projectC, List.of(tagFoo));

        projectA.addAccessTeam(team);
        projectB.addAccessTeam(team);
        // NB: Not assigning projectC

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuidA", equalTo(projectA.getUuid().toString()))
                .withMatcher("projectUuidB", equalTo(projectB.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:projectUuidA}",
                            "name": "acme-app-a"
                          },
                          {
                            "uuid": "${json-unit.matches:projectUuidB}",
                            "name": "acme-app-b"
                          }
                        ]
                        """);
    }

    @Test
    public void getTaggedProjectsWithPaginationTest() {
        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var project = new Project();
            project.setName("acme-app-" + (i + 1));
            qm.persist(project);

            qm.bind(project, List.of(tag));
        }

        Response response = jersey.target(V1_TAG + "/foo/project")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-1"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-2"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-3"
                  }
                ]
                """);

        response = jersey.target(V1_TAG + "/foo/project")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-4"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-5"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedProjectsWithTagNotExistsTest() {
        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getTaggedProjectsWithNonLowerCaseTagNameTest() {
        final Response response = jersey.target(V1_TAG + "/Foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "Value must only contain lowercase letters.",
                    "messageTemplate": "Value must only contain lowercase letters.",
                    "path": "getTaggedProjects.arg0",
                    "invalidValue": "Foo"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedPoliciesTest() {
        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.INFO);
        policyA.setTags(List.of(tagFoo));
        qm.persist(policyA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.INFO);
        policyB.setTags(List.of(tagBar));
        qm.persist(policyB);

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("policyUuidA", equalTo(policyA.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:policyUuidA}",
                            "name": "policy-a"
                          }
                        ]
                        """);
    }

    @Test
    public void getTaggedPoliciesWithPaginationTest() {
        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var policy = new Policy();
            policy.setName("policy-" + (i + 1));
            policy.setOperator(Policy.Operator.ALL);
            policy.setViolationState(Policy.ViolationState.INFO);
            policy.setTags(List.of(tag));
            qm.persist(policy);
        }

        Response response = jersey.target(V1_TAG + "/foo/policy")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-1"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-2"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-3"
                  }
                ]
                """);

        response = jersey.target(V1_TAG + "/foo/policy")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-4"
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "policy-5"
                  }
                ]
                """);
    }

    @Test
    public void getTaggedPoliciesWithTagNotExistsTest() {
        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getTaggedPoliciesWithNonLowerCaseTagNameTest() {
        final Response response = jersey.target(V1_TAG + "/Foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "Value must only contain lowercase letters.",
                    "messageTemplate": "Value must only contain lowercase letters.",
                    "path": "getTaggedPolicies.arg0",
                    "invalidValue": "Foo"
                  }
                ]
                """);
    }

    @Test
    public void getTagsForPolicyWithOrderingTest() {
        for (int i = 1; i < 5; i++) {
            qm.createTag("Tag " + i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, true, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 2"), qm.getTagByName("Tag 3"), qm.getTagByName("Tag 4")), null, null, true, false);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        Response response = jersey.target(V1_TAG + "/policy/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(4, json.size());
        Assert.assertEquals("tag 2", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getTagsForPolicyWithPolicyProjectsFilterTest() {
        for (int i = 1; i < 5; i++) {
            qm.createTag("Tag " + i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, true, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 3")), null, null, true, false);
        qm.createProject("Project C", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 4")), null, null, true, false);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy.setProjects(List.of(qm.getProject("Project A", "1"), qm.getProject("Project C", "1")));

        Response response = jersey.target(V1_TAG + "/policy/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("tag 1", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getTagWithNonUuidNameTest() {
        // NB: This is just to ensure that requests to /api/v1/tag/<value>
        // are not matched with the deprecated "getTagsForPolicy" endpoint.
        // Once we implement an endpoint to request individual tags,
        // this test should fail and adjusted accordingly.
        qm.createTag("not-a-uuid");

        final Response response = jersey.target(V1_TAG + "/not-a-uuid")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

}
