package org.dependencytrack.resources.v1;

import alpine.notification.NotificationLevel;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.ConsolePublisher;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;

import javax.json.JsonArray;
import javax.ws.rs.core.Response;
import java.util.List;

public class TagResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(TagResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getTagsWithNotificationRuleFilterTest() {
        for (int i=1; i<5; i++) {
            qm.createTag("Tag "+i);
        }
        List<Tag> projectTags = List.of(qm.getTagByName("Tag 2"), qm.getTagByName("Tag 3"), qm.getTagByName("Tag 4"));
        qm.createProject("Project", null, "1", projectTags, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.CONSOLE.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Test rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setTags(projectTags);
        qm.updateNotificationRule(rule);


        Response response = target(V1_TAG + "/rule/" + rule.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("tag 2", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getTagsWithPolicyProjectsFilterTest() {
        for (int i=1; i<5; i++) {
            qm.createTag("Tag "+i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, true, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 3")), null, null, true, false);
        qm.createProject("Project C", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 4")), null, null, true, false);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy.setProjects(List.of(qm.getProject("Project A", "1"), qm.getProject("Project C", "1")));

        Response response = target(V1_TAG + "/policy/" + policy.getUuid())
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
    public void getAllTagsWithOrderingTest() {
        for (int i=1; i<5; i++) {
            qm.createTag("Tag "+i);
        }
        qm.createProject("Project A", null, "1", List.of(qm.getTagByName("Tag 1"), qm.getTagByName("Tag 2")), null, null, true, false);
        qm.createProject("Project B", null, "1", List.of(qm.getTagByName("Tag 2"), qm.getTagByName("Tag 3"), qm.getTagByName("Tag 4")), null, null, true, false);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        Response response = target(V1_TAG + "/policy/" + policy.getUuid())
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
}
