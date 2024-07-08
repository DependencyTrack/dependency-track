package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import alpine.server.filters.AuthorizationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.resources.v1.exception.ConstraintViolationExceptionMapper;
import org.dependencytrack.resources.v1.exception.NoSuchElementExceptionMapper;
import org.dependencytrack.resources.v1.exception.TagOperationFailedExceptionMapper;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

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
                    .register(AuthorizationFilter.class)
                    .register(ConstraintViolationExceptionMapper.class)
                    .register(NoSuchElementExceptionMapper.class)
                    .register(TagOperationFailedExceptionMapper.class));

    @Test
    public void getTagsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        qm.persist(policy);

        qm.bind(policy, List.of(tagBar));

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
    public void deleteTagsTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of("foo")));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
    }

    @Test
    public void deleteTagsWhenNotExistsTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of("foo")));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) foo could not be deleted",
                  "errors": {
                    "foo": "Tag does not exist"
                  }
                }
                """);
    }

    @Test
    public void deleteTagsWhenAssignedToProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        qm.bind(project, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
    }

    @Test
    public void deleteTagsWhenAssignedToProjectWithoutPortfolioManagementPermissionTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        qm.bind(project, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 project(s), but the authenticated principal is missing the PORTFOLIO_MANAGEMENT permission."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
    }

    @Test
    public void deleteTagsWhenAssignedToInaccessibleProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        qm.createConfigProperty(
                ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ACCESS_MANAGEMENT_ACL_ENABLED.getDescription()
        );

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.bind(projectA, List.of(usedTag));
        qm.bind(projectB, List.of(usedTag));

        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 project(s) that are not accessible by the authenticated principal."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
        assertThat(qm.getTagByName("bar")).isNotNull();
    }

    @Test
    public void deleteTagsWhenAssignedToPolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        qm.bind(policy, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNull();
        assertThat(qm.getTagByName("bar")).isNull();
    }

    @Test
    public void deleteTagsWhenAssignedToPolicyWithoutPolicyManagementPermissionTest() {
        initializeWithPermissions(Permissions.TAG_MANAGEMENT);

        final Tag unusedTag = qm.createTag("foo");
        final Tag usedTag = qm.createTag("bar");

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        qm.bind(policy, List.of(usedTag));

        final Response response = jersey.target(V1_TAG)
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(unusedTag.getName(), usedTag.getName())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "Tag operation failed",
                  "detail": "The tag(s) bar could not be deleted",
                  "errors": {
                    "bar": "The tag is assigned to 1 policies, but the authenticated principal is missing the POLICY_MANAGEMENT permission."
                  }
                }
                """);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getTagByName("foo")).isNotNull();
        assertThat(qm.getTagByName("bar")).isNotNull();
    }

    @Test
    public void getTaggedProjectsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target(V1_TAG + "/Foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void tagProjectsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
        assertThat(projectB.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void tagProjectsWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "A tag with name foo does not exist"
                }
                """);
    }

    @Test
    public void tagProjectsWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "tagProjects.arg1",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void tagProjectsWithAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

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

        qm.createTag("foo");

        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
        assertThat(projectB.getTags()).isEmpty();
    }

    @Test
    public void tagProjectsWhenAlreadyTaggedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Tag tag = qm.createTag("foo");
        qm.bind(project, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void untagProjectsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final Tag tag = qm.createTag("foo");
        qm.bind(projectA, List.of(tag));
        qm.bind(projectB, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).isEmpty();
        assertThat(projectB.getTags()).isEmpty();
    }

    @Test
    public void untagProjectsWithAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

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

        final Tag tag = qm.createTag("foo");
        qm.bind(projectA, List.of(tag));
        qm.bind(projectB, List.of(tag));

        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(projectA.getUuid(), projectB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(projectA.getTags()).isEmpty();
        assertThat(projectB.getTags()).satisfiesExactly(projectTag -> assertThat(projectTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void untagProjectsWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "A tag with name foo does not exist"
                }
                """);
    }

    @Test
    public void untagProjectsWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagProjects.arg1",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagProjectsWithTooManyProjectUuidsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        qm.createTag("foo");

        final List<String> projectUuids = IntStream.range(0, 101)
                .mapToObj(ignored -> UUID.randomUUID())
                .map(UUID::toString)
                .toList();

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(projectUuids));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagProjects.arg1",
                    "invalidValue": "${json-unit.any-string}"
                  }
                ]
                """);
    }

    @Test
    public void untagProjectsWhenNotTaggedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/project")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).isEmpty();
    }

    @Test
    public void getTaggedPoliciesTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Tag tagFoo = qm.createTag("foo");
        final Tag tagBar = qm.createTag("bar");

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyB);

        qm.bind(policyA, List.of(tagFoo));
        qm.bind(policyB, List.of(tagBar));

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Tag tag = qm.createTag("foo");

        for (int i = 0; i < 5; i++) {
            final var policy = new Policy();
            policy.setName("policy-" + (i + 1));
            policy.setOperator(Policy.Operator.ALL);
            policy.setViolationState(Policy.ViolationState.INFO);
            qm.persist(policy);

            qm.bind(policy, List.of(tag));
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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target(V1_TAG + "/Foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void tagPoliciesTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyB);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(policyA.getUuid(), policyB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policyA.getTags()).satisfiesExactly(policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"));
        assertThat(policyB.getTags()).satisfiesExactly(policyTag -> assertThat(policyTag.getName()).isEqualTo("foo"));
    }

    @Test
    public void tagPoliciesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(List.of(policy.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "A tag with name foo does not exist"
                }
                """);
    }

    @Test
    public void tagPoliciesWithNoPolicyUuidsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "tagPolicies.arg1",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagPoliciesTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policyB);

        final Tag tag = qm.createTag("foo");
        qm.bind(policyA, List.of(tag));
        qm.bind(policyB, List.of(tag));

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(policyA.getUuid(), policyB.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policyA.getTags()).isEmpty();
        assertThat(policyB.getTags()).isEmpty();
    }

    @Test
    public void untagPoliciesWithTagNotExistsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(policy.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "A tag with name foo does not exist"
                }
                """);
    }

    @Test
    public void untagPoliciesWithNoProjectUuidsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(Collections.emptyList()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagPolicies.arg1",
                    "invalidValue": "[]"
                  }
                ]
                """);
    }

    @Test
    public void untagPoliciesWithTooManyPolicyUuidsTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        qm.createTag("foo");

        final List<String> policyUuids = IntStream.range(0, 101)
                .mapToObj(ignored -> UUID.randomUUID())
                .map(UUID::toString)
                .toList();

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(policyUuids));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "message": "size must be between 1 and 100",
                    "messageTemplate": "{jakarta.validation.constraints.Size.message}",
                    "path": "untagPolicies.arg1",
                    "invalidValue": "${json-unit.any-string}"
                  }
                ]
                """);
    }

    @Test
    public void untagPoliciesWhenNotTaggedTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        qm.createTag("foo");

        final Response response = jersey.target(V1_TAG + "/foo/policy")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method(HttpMethod.DELETE, Entity.json(List.of(policy.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        qm.getPersistenceManager().evictAll();
        assertThat(policy.getTags()).isEmpty();
    }

    @Test
    public void getTagsForPolicyWithOrderingTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

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
