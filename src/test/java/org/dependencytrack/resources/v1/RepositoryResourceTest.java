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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Date;
import java.util.List;

class RepositoryResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(RepositoryResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @BeforeEach
    public void before() throws Exception {
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultRepositories();
    }

    @Test
    void getRepositoriesTest() {
        Response response = jersey.target(V1_REPOSITORY).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(17), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(17, json.size());
        for (int i = 0; i < json.size(); i++) {
            Assertions.assertNotNull(json.getJsonObject(i).getString("type"));
            Assertions.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assertions.assertNotNull(json.getJsonObject(i).getString("url"));
            Assertions.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assertions.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    void getRepositoriesByTypeTest() {
        Response response = jersey.target(V1_REPOSITORY + "/MAVEN").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(5, json.size());
        for (int i = 0; i < json.size(); i++) {
            Assertions.assertEquals("MAVEN", json.getJsonObject(i).getString("type"));
            Assertions.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assertions.assertNotNull(json.getJsonObject(i).getString("url"));
            Assertions.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assertions.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    void getRepositoryMetaComponentTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/maven/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("MAVEN", json.getString("repositoryType"));
        Assertions.assertEquals("org.acme", json.getString("namespace"));
        Assertions.assertEquals("example-component", json.getString("name"));
        Assertions.assertEquals("2.0.0", json.getString("latestVersion"));
        Assertions.assertEquals(lastCheck.getTime(), json.getJsonNumber("lastCheck").longValue());
    }

    @Test
    void getRepositoryMetaComponentInvalidRepoTypeTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/generic/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(204, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void getRepositoryMetaComponentInvalidPurlTest() {
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("example-component");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "g:/g/g/g")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void getRepositoryMetaUntrackedComponentTest() {
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/maven/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The repository metadata for the specified component cannot be found.", body);
    }


    @Test
    void createRepositoryTest() {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(true);
        repository.setEnabled(true);
        repository.setUsername("testuser");
        repository.setPassword("testPassword");
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus());


        response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(18), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(18, json.size());
        Assertions.assertEquals("MAVEN", json.getJsonObject(13).getString("type"));
        Assertions.assertEquals("test", json.getJsonObject(13).getString("identifier"));
        Assertions.assertEquals("www.foobar.com", json.getJsonObject(13).getString("url"));
        Assertions.assertTrue(json.getJsonObject(13).getInt("resolutionOrder") > 0);
        Assertions.assertTrue(json.getJsonObject(13).getBoolean("authenticationRequired"));
        Assertions.assertEquals("testuser", json.getJsonObject(13).getString("username"));
        Assertions.assertTrue(json.getJsonObject(13).getBoolean("enabled"));
    }

    @Test
    void createNonInternalRepositoryTest() {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(true);
        repository.setEnabled(true);
        repository.setUsername("testuser");
        repository.setPassword("testPassword");
        repository.setInternal(false);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        RepositoryResource repositoryResource = new RepositoryResource();
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus());


        response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(18), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(18, json.size());
        Assertions.assertEquals("MAVEN", json.getJsonObject(13).getString("type"));
        Assertions.assertEquals("test", json.getJsonObject(13).getString("identifier"));
        Assertions.assertEquals("www.foobar.com", json.getJsonObject(13).getString("url"));
        Assertions.assertTrue(json.getJsonObject(13).getInt("resolutionOrder") > 0);
        Assertions.assertTrue(json.getJsonObject(13).getBoolean("authenticationRequired"));
        Assertions.assertFalse(json.getJsonObject(13).getBoolean("internal"));
        Assertions.assertEquals("testuser", json.getJsonObject(13).getString("username"));
        Assertions.assertTrue(json.getJsonObject(13).getBoolean("enabled"));
    }

    @Test
    void createRepositoryAuthFalseTest() {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(false);
        repository.setEnabled(true);
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus());


        response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(18), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(18, json.size());
        Assertions.assertEquals("MAVEN", json.getJsonObject(13).getString("type"));
        Assertions.assertEquals("test", json.getJsonObject(13).getString("identifier"));
        Assertions.assertEquals("www.foobar.com", json.getJsonObject(13).getString("url"));
        Assertions.assertTrue(json.getJsonObject(13).getInt("resolutionOrder") > 0);
        Assertions.assertFalse(json.getJsonObject(13).getBoolean("authenticationRequired"));
        Assertions.assertTrue(json.getJsonObject(13).getBoolean("enabled"));

    }

    @Test
    void updateRepositoryTest() throws Exception {
        Repository repository = new Repository();
        repository.setAuthenticationRequired(true);
        repository.setEnabled(true);
        repository.setUsername("testuser");
        repository.setPassword("testPassword");
        repository.setInternal(true);
        repository.setIdentifier("test");
        repository.setUrl("www.foobar.com");
        repository.setType(RepositoryType.MAVEN);
        Response response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                .put(Entity.entity(repository, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus());
        try (QueryManager qm = new QueryManager()) {
            List<Repository> repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    repository1.setAuthenticationRequired(false);
                    response = jersey.target(V1_REPOSITORY).request().header(X_API_KEY, apiKey)
                            .post(Entity.entity(repository1, MediaType.APPLICATION_JSON));
                    Assertions.assertEquals(200, response.getStatus());
                    break;
                }
            }
            repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    Assertions.assertEquals(false, repository1.isAuthenticationRequired());
                    break;
                }
            }
        }

    }
}
