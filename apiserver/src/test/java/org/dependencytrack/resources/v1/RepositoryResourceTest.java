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
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import com.github.packageurl.PackageURL;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

public class RepositoryResourceTest extends ResourceTest {

    private static final SecretManager secretManager = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(RepositoryResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(secretManager).to(SecretManager.class);
                        }
                    }));

    @BeforeEach
    @Override
    public void before() throws Exception {
        super.before();

        when(secretManager.getSecretMetadata(anyString()))
                .thenAnswer(invocation -> new SecretMetadata(invocation.getArgument(0), null, null, null));

        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultRepositories);
    }

    @Test
    public void getRepositoriesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

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
    public void getRepositoriesByTypeTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

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
            Assertions.assertFalse(json.getJsonObject(i).getBoolean("authenticationRequired"));
            Assertions.assertNotNull(json.getJsonObject(i).getString("identifier"));
            Assertions.assertNotNull(json.getJsonObject(i).getString("url"));
            Assertions.assertTrue(json.getJsonObject(i).getInt("resolutionOrder") > 0);
            Assertions.assertTrue(json.getJsonObject(i).getBoolean("enabled"));
        }
    }

    @Test
    public void getRepositoryMetaComponentTest() throws Exception {
        final var resolvedAt = new Date();
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/example-component"),
                        "2.0.0",
                        resolvedAt.toInstant(),
                        resolvedAt.toInstant(),
                        null,
                        null))));
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
        Assertions.assertEquals(resolvedAt.getTime(), json.getJsonNumber("lastCheck").longValue());
        Assertions.assertEquals(resolvedAt.getTime(), json.getJsonNumber("latestVersionPublishedAt").longValue());
    }

    @Test
    public void getRepositoryMetaComponentInvalidRepoTypeTest() throws Exception {
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/example-component"),
                        "2.0.0",
                        null,
                        Instant.now(),
                        null,
                        null))));
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "pkg:/generic/org.acme/example-component@1.0.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(204, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void getRepositoryMetaComponentInvalidPurlTest() throws Exception {
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/example-component"),
                        "2.0.0",
                        null,
                        Instant.now(),
                        null,
                        null))));
        Response response = jersey.target(V1_REPOSITORY + "/latest")
                .queryParam("purl", "g:/g/g/g")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void getRepositoryMetaUntrackedComponentTest() {
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
    public void createRepositoryWithBasicAuthTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "testPassword"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "MAVEN",
                  "identifier": "test",
                  "url": "www.foobar.com",
                  "resolutionOrder": "${json-unit.any-number}",
                  "enabled": true,
                  "internal": true,
                  "authenticationRequired": true,
                  "username": "testuser",
                  "password": "testPassword",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void createRepositoryWithBearerAuthTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "identifier": "test2",
                          "url": "https://www.foobar2.com",
                          "internal": true,
                          "authenticationRequired": true,
                          "password": "letoken",
                          "enabled": true,
                          "type": "MAVEN"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "MAVEN",
                  "identifier": "test2",
                  "url": "https://www.foobar2.com",
                  "resolutionOrder": "${json-unit.any-number}",
                  "enabled": true,
                  "internal": true,
                  "authenticationRequired": true,
                  "password": "letoken",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void createRepositoryWithNonExistentSecretTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        reset(secretManager);
        when(secretManager.getSecretMetadata("nonExistentSecret")).thenReturn(null);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "nonExistentSecret"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "The secret with name \"nonExistentSecret\" could not be found.");
    }

    @Test
    public void createRepositoryAuthFalseTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_READ);

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
    public void updateRepositoryTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "testPassword"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final String uuid = parseJsonObject(response).getString("uuid");

        response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "updatedSecret",
                          "uuid": "%s"
                        }
                        """.formatted(uuid)));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "MAVEN",
                  "identifier": "test",
                  "url": "www.foobar.com",
                  "resolutionOrder": "${json-unit.any-number}",
                  "enabled": true,
                  "internal": true,
                  "authenticationRequired": true,
                  "username": "testuser",
                  "password": "updatedSecret",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void updateRepositoryWithNonExistentSecretTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "testPassword"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final String uuid = parseJsonObject(response).getString("uuid");

        reset(secretManager);
        when(secretManager.getSecretMetadata("nonExistentSecret")).thenReturn(null);

        response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "nonExistentSecret",
                          "uuid": "%s"
                        }
                        """.formatted(uuid)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "The secret with name \"nonExistentSecret\" could not be found.");
    }

    @Test
    public void createRepositoryAuthRequiredWithoutPasswordTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "A password secret name is required when authentication is enabled.");
    }

    @Test
    public void updateRepositoryAuthRequiredWithoutPasswordTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "password": "testPassword"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final String uuid = parseJsonObject(response).getString("uuid");

        response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "uuid": "%s"
                        }
                        """.formatted(uuid)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "A password secret name is required when authentication is enabled.");
    }

    @Test
    public void updateRepositoryEnableAuthWithoutPasswordTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": false
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final String uuid = parseJsonObject(response).getString("uuid");

        response = jersey
                .target(V1_REPOSITORY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "type": "MAVEN",
                          "identifier": "test",
                          "url": "www.foobar.com",
                          "enabled": true,
                          "internal": true,
                          "authenticationRequired": true,
                          "username": "testuser",
                          "uuid": "%s"
                        }
                        """.formatted(uuid)));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "A password secret name is required when authentication is enabled.");
    }

    @Test
    public void authenticationNullTest() throws Exception {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        Repository repository = new Repository();
        repository.setEnabled(true);
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
                    Assertions.assertFalse(repository1.isAuthenticationRequired());
                    break;
                }
            }
            repositoryList = qm.getRepositories(RepositoryType.MAVEN).getList(Repository.class);
            for (Repository repository1 : repositoryList) {
                if (repository1.getIdentifier().equals("test")) {
                    Assertions.assertFalse(repository1.isAuthenticationRequired());
                    break;
                }
            }
        }

    }
}
