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
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.Response;
import java.util.Date;

public class RepositoryResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(RepositoryResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Before
    public void before() throws Exception {
        super.before();
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
    }

    @Test
    public void getRepositoriesTest() {
        Response response = target(V1_REPOSITORY).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(13), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(13, json.size());
        for (int i=0; i<json.size(); i++) {
            Assert.assertNotNull(json.getJsonObject(i).getString("type"));
            Assert.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assert.assertNotNull(json.getJsonObject(i).getString("url"));
            Assert.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assert.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    public void getRepositoriesByTypeTest() {
        Response response = target(V1_REPOSITORY + "/MAVEN").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(5, json.size());
        for (int i=0; i<json.size(); i++) {
            Assert.assertEquals("MAVEN", json.getJsonObject(i).getString("type"));
            Assert.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assert.assertNotNull(json.getJsonObject(i).getString("url"));
            Assert.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assert.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    public void getRepositoryMetaComponentTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/maven/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("MAVEN", json.getString("repositoryType"));
        Assert.assertEquals("org.acme", json.getString("namespace"));
        Assert.assertEquals("example-component", json.getString("name"));
        Assert.assertEquals("2.0.0", json.getString("latestVersion"));
        Assert.assertEquals(lastCheck.getTime(), json.getJsonNumber("lastCheck").longValue());
    }

    @Test
    public void getRepositoryMetaComponentInvalidRepoTypeTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/generic/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void getRepositoryMetaComponentInvalidPurlTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "g:/g/g/g")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void getRepositoryMetaUntrackedComponentTest() {
        Response response = target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/maven/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The repository metadata for the specified component cannot be found.", body);
    }
}
