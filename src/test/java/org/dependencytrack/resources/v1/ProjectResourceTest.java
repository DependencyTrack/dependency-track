/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ProjectResourceTest extends ResourceTest {

    @Override
    protected Application configure() {
        return new ResourceConfig(ProjectResource.class);
    }

    @Test
    public void getProjectsDefaultRequestTest() {
        for (int i=0; i<1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, false);
        }
        Response response = target(V1_PROJECT).request().get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("999", json.getJsonObject(0).getString("version"));
    }

    @Test
    public void getProjectsAscOrderedRequestTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, false);
        Response response = target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_ASC)
                .request().get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectsDescOrderedRequestTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, false);
        Response response = target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_DESC)
                .request().get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("DEF", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getProjectByUuidTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, false);
        Response response = target(V1_PROJECT + "/" + project.getUuid())
                .request().get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getProjectByInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, false);
        Response response = target(V1_PROJECT + "/" + UUID.randomUUID())
                .request().get(Response.class);
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
        qm.createProject("ABC", null, "1.0", tags, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, false);
        Response response = target(V1_PROJECT + "/tag/" + "production")
                .request().get(Response.class);
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
        qm.createProject("ABC", null, "1.0", tags, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, false);
        Response response = target(V1_PROJECT + "/tag/" + "stable")
                .request().get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(0, json.size());
    }
}
