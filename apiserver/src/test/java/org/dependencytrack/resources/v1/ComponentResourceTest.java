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

import alpine.common.util.UuidUtil;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import com.github.packageurl.PackageURL;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.hamcrest.Matchers.equalTo;

public class ComponentResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ComponentResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getComponentsDefaultRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(405, response.getStatus()); // No longer prohibited in DT 4.0+
    }

    @Test
    public void getComponentByUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getComponentByInvalidUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Response response = jersey.target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The component could not be found.", body);
    }

    @Test
    public void getComponentByUuidAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentByUuidWithRepositoryMetaDataTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        final var resolvedAt = new Date();
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/abc"),
                        "2.0.0",
                        null,
                        resolvedAt.toInstant(),
                        null,
                        null))));
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid())
                .queryParam("includeRepositoryMetaData", true)
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getString("name"));
        Assertions.assertEquals("MAVEN", json.getJsonObject("repositoryMeta").getString("repositoryType"));
        Assertions.assertEquals("org.acme", json.getJsonObject("repositoryMeta").getString("namespace"));
        Assertions.assertEquals("abc", json.getJsonObject("repositoryMeta").getString("name"));
        Assertions.assertEquals("2.0.0", json.getJsonObject("repositoryMeta").getString("latestVersion"));
        Assertions.assertEquals(resolvedAt.getTime(), json.getJsonObject("repositoryMeta").getJsonNumber("lastCheck").longValue());
    }

    @Test
    public void getComponentByUuidWithPublishedMetaDataTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha256("abc123def456");
        final var published = new Date();
        final var resolvedAt = new Date();
        useJdbiHandle(handle -> {
            new PackageMetadataDao(handle).upsertAll(List.of(
                    new PackageMetadata(
                            new PackageURL("pkg:maven/org.acme/abc"),
                            "2.0.0",
                            null,
                            resolvedAt.toInstant(),
                            null,
                            null)));

            new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                    new PackageArtifactMetadata(
                            new PackageURL("pkg:maven/org.acme/abc"),
                            new PackageURL("pkg:maven/org.acme/abc"),
                            null,
                            null,
                            "abc123def456",
                            null,
                            published.toInstant(),
                            null,
                            null,
                            published.toInstant())));
        });
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid())
                .queryParam("includeRepositoryMetaData", true)
                .queryParam("includeIntegrityMetaData", true)
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getString("name"));
        Assertions.assertEquals("MAVEN", json.getJsonObject("repositoryMeta").getString("repositoryType"));
        Assertions.assertEquals("org.acme", json.getJsonObject("repositoryMeta").getString("namespace"));
        Assertions.assertEquals("abc", json.getJsonObject("repositoryMeta").getString("name"));
        Assertions.assertEquals("2.0.0", json.getJsonObject("repositoryMeta").getString("latestVersion"));
        Assertions.assertEquals(resolvedAt.getTime(), json.getJsonObject("repositoryMeta").getJsonNumber("lastCheck").longValue());
        Assertions.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonObject("componentMetaInformation").getJsonNumber("publishedDate").longValue() / 1000)).toString());
        Assertions.assertEquals(HASH_MATCH_PASSED.toString(), json.getJsonObject("componentMetaInformation").getString("integrityMatchStatus"));
        Assertions.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonObject("componentMetaInformation").getJsonNumber("lastFetched").longValue() / 1000)).toString());
    }

    @Test
    public void getComponentByIdentityWithCoordinatesTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("group", "groupB")
                .queryParam("name", "nameB")
                .queryParam("version", "versionB")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("acme-app-accessible");
        accessibleProject.addAccessTeam(super.team);
        qm.persist(accessibleProject);

        final var accessibleComponent = new Component();
        accessibleComponent.setProject(accessibleProject);
        accessibleComponent.setName("acme-lib");
        qm.persist(accessibleComponent);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final var inaccessibleComponent = new Component();
        inaccessibleComponent.setProject(inaccessibleProject);
        inaccessibleComponent.setName("acme-lib");
        qm.persist(inaccessibleComponent);

        Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("name", "acme-lib")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final String responseJson = getPlainTextBody(response);
        assertThatJson(responseJson).isArray().hasSize(1);
        assertThatJson(responseJson).inPath("$[0].uuid").isEqualTo(accessibleComponent.getUuid().toString());
    }

    @Test
    public void getDependencyGraphForComponentTestWithRepositoryMetaData() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component1 = new Component();
        component1.setProject(project);
        component1.setName("Component1");
        component1.setVersion("1.0.0");
        component1.setPurl("pkg:maven/org.acme/component1");
        component1 = qm.createComponent(component1, false);

        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setName("Component1_1");
        component1_1.setVersion("2.0.0");
        component1_1.setPurl("pkg:maven/org.acme/component1_1");
        component1_1 = qm.createComponent(component1_1, false);

        Component component1_1_1 = new Component();
        component1_1_1.setProject(project);
        component1_1_1.setName("Component1_1_1");
        component1_1_1.setVersion("3.0.0");
        component1_1_1.setPurl("pkg:maven/org.acme/component1_1_1");
        component1_1_1 = qm.createComponent(component1_1_1, false);

        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/component1"),
                        "2.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null),
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/component1_1"),
                        "3.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null),
                new PackageMetadata(
                        new PackageURL("pkg:maven/org.acme/component1_1_1"),
                        "4.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null))));

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        component1_1.setDirectDependencies("[{\"uuid\":\"" + component1_1_1.getUuid() + "\"}]");

        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component1_1_1.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assertions.assertEquals(200, response.getStatus(), 0);

        Assertions.assertTrue(json.get(component1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertEquals("2.0.0", json.get(component1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
        Assertions.assertTrue(json.get(component1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertEquals("3.0.0", json.get(component1_1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
        Assertions.assertFalse(json.get(component1_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertEquals("4.0.0", json.get(component1_1_1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
    }

    @Test
    public void getComponentByIdentityWithPurlTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("purl", "pkg:maven/groupB/nameB@versionB")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityWithCpeTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("cpe", "cpe:2.3:a:groupB:nameB:versionB")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityWithProjectTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("group");
        componentA.setName("name");
        componentA.setVersion("version");
        componentA.setPurl("pkg:maven/group/name@version?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("group");
        componentB.setName("name");
        componentB.setVersion("version");
        componentB.setPurl("pkg:maven/group/name@version?foo=bar");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("purl", "pkg:maven/group/name@version")
                .queryParam("project", projectB.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityWithProjectWhenProjectDoesNotExistTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Response response = jersey
                .target(V1_COMPONENT + "/identity")
                .queryParam("purl", "pkg:maven/group/name@version")
                .queryParam("project", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("The project could not be found");
    }

    @Test
    void getComponentByIdentityExcludeInactiveProjectsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project activeProject = qm.createProject("activeProject", null, "1.0", null, null, null, null, false);
        var activeComponent = new Component();
        activeComponent.setProject(activeProject);
        activeComponent.setGroup("acme");
        activeComponent.setName("library");
        activeComponent.setVersion("1.0");
        activeComponent.setPurl("pkg:maven/acme/library@1.0");
        activeComponent = qm.createComponent(activeComponent, false);

        final Project inactiveProject = qm.createProject("inactiveProject", null, "1.0", null, null, null, new Date(), false);
        var inactiveComponent = new Component();
        inactiveComponent.setProject(inactiveProject);
        inactiveComponent.setGroup("acme");
        inactiveComponent.setName("library");
        inactiveComponent.setVersion("1.0");
        inactiveComponent.setPurl("pkg:maven/acme/library@1.0");
        qm.createComponent(inactiveComponent, false);

        final Response response = jersey
                .target(V1_COMPONENT + "/identity")
                .queryParam("name", "library")
                .queryParam("excludeInactiveProjects", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);
        assertThat(json.getJsonObject(0).getString("uuid")).isEqualTo(activeComponent.getUuid().toString());
    }

    @Test
    void getComponentByIdentityOnlyLatestProjectVersionTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project latestProject = qm.createProject("latestProject", null, "2.0", null, null, null, null, true, false);
        var latestComponent = new Component();
        latestComponent.setProject(latestProject);
        latestComponent.setGroup("acme");
        latestComponent.setName("library");
        latestComponent.setVersion("1.0");
        latestComponent.setPurl("pkg:maven/acme/library@1.0");
        latestComponent = qm.createComponent(latestComponent, false);

        final Project olderProject = qm.createProject("olderProject", null, "1.0", null, null, null, null, false);
        var olderComponent = new Component();
        olderComponent.setProject(olderProject);
        olderComponent.setGroup("acme");
        olderComponent.setName("library");
        olderComponent.setVersion("1.0");
        olderComponent.setPurl("pkg:maven/acme/library@1.0");
        qm.createComponent(olderComponent, false);

        final Response response = jersey
                .target(V1_COMPONENT + "/identity")
                .queryParam("name", "library")
                .queryParam("onlyLatestProjectVersions", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);
        assertThat(json.getJsonObject(0).getString("uuid")).isEqualTo(latestComponent.getUuid().toString());
    }

    @Test
    void getComponentByIdentityExcludeInactiveAndOnlyLatestProjectVersionTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project activeLatest = qm.createProject("activeLatest", null, "2.0", null, null, null, null, true, false);
        var activeLatestComponent = new Component();
        activeLatestComponent.setProject(activeLatest);
        activeLatestComponent.setGroup("acme");
        activeLatestComponent.setName("library");
        activeLatestComponent.setVersion("1.0");
        activeLatestComponent.setPurl("pkg:maven/acme/library@1.0");
        activeLatestComponent = qm.createComponent(activeLatestComponent, false);

        final Project activeOlder = qm.createProject("activeOlder", null, "1.0", null, null, null, null, false);
        var activeOlderComponent = new Component();
        activeOlderComponent.setProject(activeOlder);
        activeOlderComponent.setGroup("acme");
        activeOlderComponent.setName("library");
        activeOlderComponent.setVersion("1.0");
        activeOlderComponent.setPurl("pkg:maven/acme/library@1.0");
        qm.createComponent(activeOlderComponent, false);

        final Project inactiveLatest = qm.createProject("inactiveLatest", null, "2.0", null, null, null, new Date(), true, false);
        var inactiveLatestComponent = new Component();
        inactiveLatestComponent.setProject(inactiveLatest);
        inactiveLatestComponent.setGroup("acme");
        inactiveLatestComponent.setName("library");
        inactiveLatestComponent.setVersion("1.0");
        inactiveLatestComponent.setPurl("pkg:maven/acme/library@1.0");
        qm.createComponent(inactiveLatestComponent, false);

        final Response response = jersey
                .target(V1_COMPONENT + "/identity")
                .queryParam("name", "library")
                .queryParam("excludeInactiveProjects", "true")
                .queryParam("onlyLatestProjectVersions", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);
        assertThat(json.getJsonObject(0).getString("uuid")).isEqualTo(activeLatestComponent.getUuid().toString());
    }

    @Test
    public void getComponentByHashTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/hash/" + component.getSha1())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "1");
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getComponentByInvalidHashTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Response response = jersey.target(V1_COMPONENT + "/hash/c5a8829aa3da800216b933e265dd0b97eb6f9341")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "0");
    }

    @Test
    public void createComponentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        List<OrganizationalContact> authors = new ArrayList<>();
        authors.add(new OrganizationalContact(){{
            setName("SampleAuthor");
        }});
        component.setAuthors(authors);
        component.setClassifier(Classifier.APPLICATION);
        component.setPurl("pkg:maven/org.acme/abc");
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("My Component", json.getString("name"));
        Assertions.assertEquals("1.0", json.getString("version"));
        Assertions.assertEquals("SampleAuthor" ,json.getJsonArray("authors").getJsonObject(0).getString("name"));
        Assertions.assertEquals("APPLICATION", json.getString("classifier"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void createComponentUpperCaseHashTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component.setClassifier(Classifier.LIBRARY);
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha1("640ab2bae07bedc4c163f679a746f7ab7fb5d1fa".toUpperCase());
        component.setSha256("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25".toUpperCase());
        component.setSha3_256("c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0".toUpperCase());
        component.setSha384("7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3".toUpperCase());
        component.setSha3_384("da73bfcba560692a019f52c37de4d5e3ab49ca39c6a75594e3c39d805388c4de9d0ff3927eb9e197536f5b0b3a515f0a".toUpperCase());
        component.setSha512("c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31".toUpperCase());
        component.setSha3_512("301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7".toUpperCase());
        component.setMd5("0cbc6611f5540bd0809a388dc95a615b".toUpperCase());
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("My Component", json.getString("name"));
        Assertions.assertEquals("1.0", json.getString("version"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assertions.assertEquals(component.getSha1(), json.getString("sha1"));
        Assertions.assertEquals(component.getSha256(), json.getString("sha256"));
        Assertions.assertEquals(component.getSha3_256(), json.getString("sha3_256"));
        Assertions.assertEquals(component.getSha384(), json.getString("sha384"));
        Assertions.assertEquals(component.getSha3_384(), json.getString("sha3_384"));
        Assertions.assertEquals(component.getSha512(), json.getString("sha512"));
        Assertions.assertEquals(component.getSha3_512(), json.getString("sha3_512"));
        Assertions.assertEquals(component.getMd5(), json.getString("md5"));
    }

    @Test
    public void createComponentAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-lib",
                          "classifier": "LIBRARY"
                        }
                        """));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(201);
    }

    @Test
    public void updateComponentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setPurl("pkg:maven/org.acme/abc");
        component.setName("My Component");
        component.setVersion("1.0");
        component.setClassifier(Classifier.APPLICATION);
        qm.createComponent(component, false);

        var jsonComponent = new Component();
        jsonComponent.setUuid(component.getUuid());
        jsonComponent.setPurl("pkg:maven/org.acme/abc");
        jsonComponent.setName("My Component");
        jsonComponent.setVersion("1.0");
        jsonComponent.setClassifier(Classifier.LIBRARY);
        jsonComponent.setDescription("Test component");
        var externalReference = new ExternalReference();
        externalReference.setType(org.cyclonedx.model.ExternalReference.Type.WEBSITE);
        externalReference.setUrl("test.com");
        jsonComponent.setExternalReferences(List.of(externalReference));

        Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonComponent, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("My Component", json.getString("name"));
        Assertions.assertEquals("1.0", json.getString("version"));
        Assertions.assertEquals("Test component", json.getString("description"));
        Assertions.assertEquals("LIBRARY", json.getString("classifier"));
        Assertions.assertEquals(1, json.getJsonArray("externalReferences").size());
    }

    @Test
    public void shouldRejectUpdateWithEmptyName() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        final Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {
                          "uuid": "%s",
                          "name": "",
                          "classifier": "LIBRARY"
                        }
                        """.formatted(component.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void shouldRejectCreateWithEmptyName() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "name": "",
                          "classifier": "LIBRARY"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void shouldUpdateComponentWithEmptyOptionalFields() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setClassifier(Classifier.LIBRARY);
        component.setDescription("some description");
        component.setLicense("Apache-2.0");
        component.setCopyright("Copyright Acme");
        qm.persist(component);

        final Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {
                          "uuid": "%s",
                          "name": "acme-lib",
                          "classifier": "LIBRARY",
                          "version": "",
                          "group": "",
                          "description": "",
                          "license": "",
                          "licenseExpression": "",
                          "licenseUrl": "",
                          "filename": "",
                          "cpe": "",
                          "swidTagId": "",
                          "copyright": "",
                          "md5": "",
                          "sha1": "",
                          "sha256": "",
                          "sha512": "",
                          "sha3_256": "",
                          "sha3_512": ""
                        }
                        """.formatted(component.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();
        final Component updated = qm.getObjectByUuid(Component.class, component.getUuid());
        assertThat(updated.getVersion()).isNull();
        assertThat(updated.getGroup()).isNull();
        assertThat(updated.getDescription()).isNull();
        assertThat(updated.getLicense()).isNull();
        assertThat(updated.getLicenseExpression()).isNull();
        assertThat(updated.getLicenseUrl()).isNull();
        assertThat(updated.getFilename()).isNull();
        assertThat(updated.getCpe()).isNull();
        assertThat(updated.getSwidTagId()).isNull();
        assertThat(updated.getCopyright()).isNull();
        assertThat(updated.getMd5()).isNull();
        assertThat(updated.getSha1()).isNull();
        assertThat(updated.getSha256()).isNull();
        assertThat(updated.getSha512()).isNull();
        assertThat(updated.getSha3_256()).isNull();
        assertThat(updated.getSha3_512()).isNull();
    }

    @Test
    public void updateComponentInvalidLicenseExpressionTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var jsonComponent = new Component();
        jsonComponent.setName("acme-lib");
        jsonComponent.setVersion("1.0.0");
        jsonComponent.setLicenseExpression("(invalid");

        final Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "uuid": "%s",
                          "name": "acme-lib",
                          "version": "1.0.0",
                          "classifier": "LIBRARY",
                          "licenseExpression": "(invalid"
                        }
                        """.formatted(component.getUuid()), MediaType.APPLICATION_JSON_TYPE));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).
                isEqualTo("""
                        [
                          {
                            "message": "The license expression must be a valid SPDX expression",
                            "messageTemplate": "The license expression must be a valid SPDX expression",
                            "path": "licenseExpression",
                            "invalidValue": "(invalid"
                          }
                        ]
                        """);
    }

    @Test
    public void updateComponentAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "acme-lib-foobar",
                          "classifier": "LIBRARY"
                        }
                        """.formatted(component.getUuid())));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void deleteComponentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setUuid(UUID.randomUUID());
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid().toString())
                .request().header(X_API_KEY, apiKey).delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentInvalidUuidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    public void internalComponentIdentificationTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);
        Response response = jersey.target(V1_COMPONENT + "/internal/identify")
                .request().header(X_API_KEY, apiKey).get();
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component1 = new Component();
        component1.setProject(project);
        component1.setName("Component1");
        component1 = qm.createComponent(component1, false);

        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setName("Component1_1");
        component1_1 = qm.createComponent(component1_1, false);

        Component component1_1_1 = new Component();
        component1_1_1.setProject(project);
        component1_1_1.setName("Component1_1_1");
        component1_1_1 = qm.createComponent(component1_1_1, false);

        Component component2 = new Component();
        component2.setProject(project);
        component2.setName("Component2");
        component2 = qm.createComponent(component2, false);

        Component component2_1 = new Component();
        component2_1.setProject(project);
        component2_1.setName("Component2_1");
        component2_1 = qm.createComponent(component2_1, false);

        Component component2_1_1 = new Component();
        component2_1_1.setProject(project);
        component2_1_1.setName("Component2_1_1");
        component2_1_1 = qm.createComponent(component2_1_1, false);

        Component component2_1_1_1 = new Component();
        component2_1_1_1.setProject(project);
        component2_1_1_1.setName("Component2_1_1");
        component2_1_1_1 = qm.createComponent(component2_1_1_1, false);

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}, {\"uuid\":\"" + component2.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        component1_1.setDirectDependencies("[{\"uuid\":\"" + component1_1_1.getUuid() + "\"}]");
        component2.setDirectDependencies("[{\"uuid\":\"" + component2_1.getUuid() + "\"}]");
        component2_1.setDirectDependencies("[{\"uuid\":\"" + component2_1_1.getUuid() + "\"}]");
        component2_1_1.setDirectDependencies("[{\"uuid\":\"" + component2_1_1_1.getUuid() + "\"}]");

        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component1_1_1.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assertions.assertEquals(200, response.getStatus(), 0);

        Assertions.assertTrue(json.get(component1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertTrue(json.get(component1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertFalse(json.get(component1_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertFalse(json.get(component2.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertFalse(json.get(component2_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assertions.assertFalse(json.get(component2_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Component finalComponent2_1_1_1 = component2_1_1_1;
        Assertions.assertThrows(NullPointerException.class, () -> json.get(finalComponent2_1_1_1.getUuid().toString()).asJsonObject().asJsonObject());
    }

    @Test
    public void getDependencyGraphForComponentInvalidProjectUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/project/" + UUID.randomUUID() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentInvalidComponentUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get();
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentNoDependencyGraphTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(0, json.size());
    }

    @Test
    public void getDependencyGraphForComponentIsNotComponentOfProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project projectWithComponent = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(projectWithComponent);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        projectWithComponent.setDirectDependencies("[{\"uuid\":\"" + component.getUuid() + "\"}]");
        Project projectWithoutComponent = qm.createProject("Acme Library", null, null, null, null, null, null, false);
        Response responseWithComponent = jersey.target(V1_COMPONENT + "/project/" + projectWithComponent.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject jsonWithComponent = parseJsonObject(responseWithComponent);
        Assertions.assertEquals(200, responseWithComponent.getStatus(), 0);
        Assertions.assertEquals(1, jsonWithComponent.size());
        Response responseWithoutComponent = jersey.target(V1_COMPONENT + "/project/" + projectWithoutComponent.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject jsonWithoutComponent = parseJsonObject(responseWithoutComponent);
        Assertions.assertEquals(200, responseWithoutComponent.getStatus(), 0);
        Assertions.assertEquals(0, jsonWithoutComponent.size());
    }

    @Test
    public void getDependencyGraphForComponentAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getOccurrencesTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var occurrenceA = new ComponentOccurrence();
        occurrenceA.setComponent(component);
        occurrenceA.setLocation("/foo/bar");
        qm.persist(occurrenceA);

        final var occurrenceB = new ComponentOccurrence();
        occurrenceB.setComponent(component);
        occurrenceB.setLocation("/foo/bar/baz");
        occurrenceB.setLine(5);
        occurrenceB.setOffset(666);
        occurrenceB.setSymbol("someSymbol");
        qm.persist(occurrenceB);

        final Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid() + "/occurrence")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("occurrenceIdA", equalTo(occurrenceA.getId().toString()))
                .withMatcher("occurrenceIdB", equalTo(occurrenceB.getId().toString()))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "id": "${json-unit.matches:occurrenceIdA}",
                            "location": "/foo/bar",
                            "createdAt": "${json-unit.any-number}"
                          },
                          {
                            "id": "${json-unit.matches:occurrenceIdB}",
                            "location": "/foo/bar/baz",
                            "line": 5,
                            "offset": 666,
                            "symbol": "someSymbol",
                            "createdAt": "${json-unit.any-number}"
                          }
                        ]
                        """);
    }

    @Test
    public void getOccurrencesComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Response response = jersey.target(V1_COMPONENT + "/aa684b6f-de53-4249-a2b1-bf16ac458328/occurrence")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Component could not be found"
                }
                """);
    }

    @Test
    public void getOccurrencesAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid() + "/occurrence")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThatJson(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void shouldRejectComponentCreationForCollectionProject() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT, Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = new Project();
        project.setName("acme-app");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(project, List.of(), false);

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-lib",
                          "version": "1.0.0",
                          "classifier": "LIBRARY"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("A collection project cannot contain components.");
    }

}
