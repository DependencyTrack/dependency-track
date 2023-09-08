/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import static org.assertj.core.api.Assertions.assertThat;
import alpine.common.util.UuidUtil;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.cyclonedx.model.ExternalReference.Type;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class ProjectResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(ProjectResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getProjectsDefaultRequestTest() {
        for (int i=0; i<1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, true, false);
        }
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("999", json.getJsonObject(0).getString("version"));
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2583
    public void getProjectsWithAclEnabledTest() {
        // Enable portfolio access control.
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        // Create project and give access to current principal's team.
        final Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        // Create a second project that the current principal has no access to.
        qm.createProject("acme-app-b", null, "2.0.0", null, null, null, true, false);

        final Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());
        Assert.assertEquals("acme-app-a", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("1.0.0", json.getJsonObject(0).getString("version"));
    }

    @Test
    public void getProjectsByNameRequestTest() {
        for (int i=0; i<1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, true, false);
        }
        Response response = target(V1_PROJECT)
                .queryParam("name", "Acme Example")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("999", json.getJsonObject(0).getString("version"));
    }

    @Test
    public void getProjectsByInvalidNameRequestTest() {
        for (int i=0; i<1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, true, false);
        }
        Response response = target(V1_PROJECT)
                .queryParam("name", "blah")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(0, json.size());
    }

    @Test
    public void getProjectsByNameActiveOnlyRequestTest() {
        for (int i=0; i<500; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, true, false);
        }
        for (int i=500; i<1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, false, false);
        }
        Response response = target(V1_PROJECT)
                .queryParam("name", "Acme Example")
                .queryParam("excludeInactive", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(500), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
    }

    @Test
    public void getProjectLookupTest() {
        for (int i=0; i<500; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, false, false);
        }
        Response response = target(V1_PROJECT+"/lookup")
                .queryParam("name", "Acme Example")
                .queryParam("version", "10")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
                Assert.assertEquals(200, response.getStatus(), 0);
                Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Acme Example", json.getString("name"));
        Assert.assertEquals("10", json.getString("version"));
        Assert.assertEquals(500, json.getJsonArray("versions").size());
        Assert.assertNotNull(json.getJsonArray("versions").getJsonObject(100).getString("uuid"));
        Assert.assertNotEquals("", json.getJsonArray("versions").getJsonObject(100).getString("uuid"));
        Assert.assertEquals("100", json.getJsonArray("versions").getJsonObject(100).getString("version"));
    }

    @Test
    public void getProjectsAscOrderedRequestTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        qm.createProject("DEF", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_ASC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectsDescOrderedRequestTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        qm.createProject("DEF", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_DESC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("DEF", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectByUuidTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("versions").size());
        Assert.assertEquals(project.getUuid().toString(), json.getJsonArray("versions").getJsonObject(0).getJsonString("uuid").getString());
        Assert.assertEquals("1.0", json.getJsonArray("versions").getJsonObject(0).getJsonString("version").getString());
    }

    @Test
    public void getProjectByInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getProjectByTagTest() {
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("production");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, true, false);
        qm.createProject("DEF", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/tag/" + "production")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectByCaseInsensitiveTagTest() {
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("PRODUCTION");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, true, false);
        qm.createProject("DEF", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/tag/" + "production")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectByUnknownTagTest() {
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("production");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, true, false);
        qm.createProject("DEF", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/tag/" + "stable")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(0, json.size());
    }

    @Test
    public void createProjectTest(){
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        project.setDescription("Test project");
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Acme Example", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test project", json.getString("description"));
        Assert.assertTrue(json.getBoolean("active"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void createProjectDuplicateTest() {
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A project with the specified name already exists.", body);
    }

    @Test
    public void createProjectEmptyTest() {
        Project project = new Project();
        project.setName(" ");
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateProjectTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        project.setDescription("Test project");
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test project", json.getString("description"));
    }

    @Test
    public void updateProjectTestIsActiveEqualsNull() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        project.setDescription("Test project");
        project.setActive(null);
        Assert.assertNull(project.isActive());
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test project", json.getString("description"));
    }

    @Test
    public void updateProjectTagsTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, true, false);

        final var jsonProject = new Project();
        jsonProject.setUuid(p1.getUuid());
        jsonProject.setName(p1.getName());
        jsonProject.setVersion(p1.getVersion());
        jsonProject.setTags(Stream.of("tag1", "tag2", "tag3").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toList()));

        // update the 1st time and add another tag
        var response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        var json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(p1.getName(), json.getString("name"));
        Assert.assertEquals(p1.getVersion(), json.getString("version"));
        Assert.assertFalse(json.containsKey("description"));
        var jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(3, jsonTags.size());
        Assert.assertEquals("tag1", jsonTags.get(0).asJsonObject().getString("name"));
        Assert.assertEquals("tag2", jsonTags.get(1).asJsonObject().getString("name"));
        Assert.assertEquals("tag3", jsonTags.get(2).asJsonObject().getString("name"));

        // and update again with the same tags ... issue #1165
        response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        json = parseJsonObject(response);
        jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(3, jsonTags.size());
        Assert.assertEquals("tag1", jsonTags.get(0).asJsonObject().getString("name"));
        Assert.assertEquals("tag2", jsonTags.get(1).asJsonObject().getString("name"));
        Assert.assertEquals("tag3", jsonTags.get(2).asJsonObject().getString("name"));

        // and finally delete one of the tags
        jsonProject.getTags().remove(0);
        response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        json = parseJsonObject(response);
        jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(2, jsonTags.size());
        Assert.assertEquals("tag2", jsonTags.get(0).asJsonObject().getString("name"));
        Assert.assertEquals("tag3", jsonTags.get(1).asJsonObject().getString("name"));
    }

    @Test
    public void updateProjectEmptyNameTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        project.setName(" ");
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateProjectDuplicateTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Project project = qm.createProject("DEF", null, "1.0", null, null, null, true, false);
        project.setName("ABC");
        Response response = target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A project with the specified name and version already exists.", body);
    }

    @Test
    public void deleteProjectTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/" + project.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteProjectInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Response response = target(V1_PROJECT + "/" + UUID.randomUUID().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void patchProjectNotModifiedTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, true, false);

        final var jsonProject = new Project();
        jsonProject.setDescription(p1.getDescription());
        final var response = target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.NOT_MODIFIED.getStatusCode(), response.getStatus());
        Assert.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    public void patchProjectNameVersionConflictTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, true, false);
        qm.createProject("ABC", "Test project", "0.9", null, null, null, false, false);
        final var jsonProject = new Project();
        jsonProject.setVersion("0.9");
        final var response = target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.CONFLICT.getStatusCode(), response.getStatus());
        Assert.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    public void patchProjectNotFoundTest() {
        final var response = target(V1_PROJECT + "/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(new Project()));
        Assert.assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
    }

    @Test
    public void patchProjectSuccessfullyPatchedTest() {
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, true, false);
        final var jsonProject = new Project();
        jsonProject.setActive(false);
        jsonProject.setName("new name");
        jsonProject.setPublisher("new publisher");
        jsonProject.setTags(Stream.of("tag4").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toUnmodifiableList()));
        final var response = target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        final var json = parseJsonObject(response);
        Assert.assertEquals(p1.getUuid().toString(), json.getString("uuid"));
        Assert.assertEquals(p1.getDescription(), json.getString("description"));
        Assert.assertEquals(p1.getVersion(), json.getString("version"));
        Assert.assertEquals(jsonProject.getName(), json.getString("name"));
        Assert.assertEquals(jsonProject.getPublisher(), json.getString("publisher"));
        Assert.assertEquals(false, json.getBoolean("active"));
        final var jsonTags = json.getJsonArray("tags");
        Assert.assertEquals(1, jsonTags.size());
        Assert.assertEquals("tag4", jsonTags.get(0).asJsonObject().getString("name"));
    }

    @Test
    public void patchProjectExternalReferencesTest() {
        final var project = qm.createProject("referred-project", "ExtRef test project", "1.0", null, null, null, true, false);
        final var ref1 = new ExternalReference();
        ref1.setType(Type.VCS);
        ref1.setUrl("https://github.com/DependencyTrack/awesomeness");
        final var ref2 = new ExternalReference();
        ref2.setType(Type.WEBSITE);
        ref2.setUrl("https://dependencytrack.org");
        ref2.setComment("Worth a visit!");
        final var externalReferences = List.of(ref1, ref2);
        final var jsonProject = new Project();
        jsonProject.setExternalReferences(externalReferences);

        final var response = target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));

        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        final var json = parseJsonObject(response);
        final var patchedExternalReferences = json.getJsonArray("externalReferences");
        Assert.assertEquals(2, patchedExternalReferences.size());
        final var patchedRef1 = patchedExternalReferences.getJsonObject(0);
        final var patchedRef2 = patchedExternalReferences.getJsonObject(1);
        Assert.assertEquals("vcs", patchedRef1.getString("type"));
        Assert.assertEquals("https://github.com/DependencyTrack/awesomeness", patchedRef1.getString("url"));
        Assert.assertEquals("website", patchedRef2.getString("type"));
        Assert.assertEquals("https://dependencytrack.org", patchedRef2.getString("url"));
        Assert.assertEquals("Worth a visit!", patchedRef2.getString("comment"));
    }

    @Test
    public void patchProjectParentTest() {
        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        final Project project = qm.createProject("DEF", null, "2.0", null, parent, null, true, false);
        final Project newParent = qm.createProject("GHI", null, "3.0", null, null, null, true, false);

        final JsonObject jsonProject = Json.createObjectBuilder()
                .add("parent", Json.createObjectBuilder()
                        .add("uuid", newParent.getUuid().toString()))
                .build();

        final Response response = target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject.toString()));

        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson.getString("uuid")).isEqualTo(project.getUuid().toString());
        assertThat(responseJson.getJsonObject("parent")).isNull(); // Parents are currently not returned

        // Ensure the parent was updated.
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getParent()).isNotNull();
        assertThat(project.getParent().getUuid()).isEqualTo(newParent.getUuid());
    }

    @Test
    public void patchProjectParentNotFoundTest() {
        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        final Project project = qm.createProject("DEF", null, "2.0", null, parent, null, true, false);

        final JsonObject jsonProject = Json.createObjectBuilder()
                .add("parent", Json.createObjectBuilder()
                        .add("uuid", UUID.randomUUID().toString()))
                .build();

        final Response response = target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject.toString()));

        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the parent project could not be found.");

        // Ensure the parent was not modified.
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getParent()).isNotNull();
        assertThat(project.getParent().getUuid()).isEqualTo(parent.getUuid());
    }

    @Test
    public void getRootProjectsTest() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, true, false);
        qm.createProject("GHI", null, "1.0", null, child, null, true, false);
        Response response = target(V1_PROJECT)
                .queryParam("onlyRoot", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
        Assert.assertThrows(IndexOutOfBoundsException.class, () -> json.getJsonObject(1));
    }

    @Test
    public void getChildrenProjectsTest() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, true, false);
        qm.createProject("GHI", null, "1.0", null, parent, null, true, false);
        qm.createProject("JKL", null, "1.0", null, child, null, true, false);
        Response response = target(V1_PROJECT + "/" + parent.getUuid().toString() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("DEF", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("GHI", json.getJsonObject(1).getString("name"));
    }

    @Test
    public void updateChildAsParentOfChild() {
        Project parent = qm.createProject("ABC",null, "1.0", null, null, null, true, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, true, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setActive(true);

        tmpProject.setParent(child);
        Assert.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    public void updateParentToInactiveWithActiveChild() {
        Project parent = qm.createProject("ABC",null, "1.0", null, null, null, true, false);
        qm.createProject("DEF", null, "1.0", null, parent, null, true, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setActive(false);

        Assert.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    public void updateProjectParentToSelf() {
        Project parent = qm.createProject("ABC",null, "1.0", null, null, null, true, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setActive(parent.isActive());
        tmpProject.setParent(parent);

        Assert.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    public void getProjectsWithoutDescendantsOfTest() {
        Project grandParent = qm.createProject("ABC",null, "1.0", null, null, null, true, false);
        Project parent = qm.createProject("DEF", null, "1.0", null, grandParent, null, true, false);
        Project child = qm.createProject("GHI", null, "1.0", null, parent, null, true, false);
        qm.createProject("JKL", null, "1.0", null, child, null, true, false);

        Response response = target(V1_PROJECT + "/withoutDescendantsOf/" + parent.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    //todo: add clone tests
}
