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

import alpine.filters.ApiFilter;
import alpine.filters.AuthenticationFilter;
import alpine.util.UuidUtil;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
    public void createProjectTest() {
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

    //todo: add clone tests
}
