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
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonReader;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.util.PurlUtil;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.StringReader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.hamcrest.Matchers.equalTo;

public class ComponentResourcePostgresTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ComponentResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getAllComponentsTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = prepareProject();

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1000"); // 1000 dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100); // Default page size is 100
        assertThatJson(json.getFirst().toString())
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        {
                          "authors": [
                            {
                              "name": "author-0"
                            }
                          ],
                          "group": "component-group",
                          "name": "component-name-0",
                          "version": "0.0",
                          "purl": "pkg:maven/component-group/component-name-0@0.0",
                          "project": {
                            "name": "Acme Application",
                            "directDependencies": "${json-unit.any-string}",
                            "uuid": "${json-unit.matches:projectUuid}",
                            "isLatest": false,
                            "active": true
                          },
                          "uuid": "${json-unit.any-string}",
                          "repositoryMeta": {
                            "repositoryType": "MAVEN",
                            "namespace": "component-group",
                            "name": "component-name-0",
                            "latestVersion": "0.0",
                            "lastCheck": "${json-unit.any-number}"
                          },
                          "componentMetaInformation": {
                            "integrityMatchStatus": "COMPONENT_MISSING_HASH"
                          },
                          "expandDependencyGraph": false,
                          "isInternal": false,
                          "occurrenceCount": 0
                        }
                        """);
    }

    @Test
    public void getOutdatedComponentsTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = prepareProject();

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("onlyOutdated", true)
                .queryParam("onlyDirect", false)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("200"); // 200 outdated dependencies,  direct and transitive

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100); // Default page size is 100
    }

    @Test
    public void getOutdatedDirectComponentsTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = prepareProject();

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("onlyOutdated", true)
                .queryParam("onlyDirect", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("75"); // 75 outdated direct dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(75);
    }

    @Test
    public void getAllDirectComponentsTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = prepareProject();

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("onlyDirect", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("100"); // 100 direct dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100);
    }

    @Test
    public void getAllComponentsFilterTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("Acme-Lib-A");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("aCme-lIb-b");
        qm.persist(componentB);

        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setName("somethingCompletelyDifferent");
        qm.persist(componentC);

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("searchText", "ACME")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThat(parseJsonArray(response)).satisfiesExactly(
                component -> assertThat(component.asJsonObject().getString("name")).isEqualTo("Acme-Lib-A"),
                component -> assertThat(component.asJsonObject().getString("name")).isEqualTo("aCme-lIb-b")
        );
    }

    @Test
    public void getComponentsByNameTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = prepareProject();

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("searchText", "name-1")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("111"); // 75 outdated direct dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100);
    }

    @Test
    public void getComponentsByGroupTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = prepareProject();

        final Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("searchText", "group")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1000"); // 75 outdated direct dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100);
    }

    private Project prepareProject() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final List<String> directDepencencies = new ArrayList<>();
        final List<PackageMetadata> packageMetadataList = new ArrayList<>();
        final List<PackageArtifactMetadata> artifactMetadataList = new ArrayList<>();
        // Generate 1000 dependencies
        for (int i = 0; i < 1000; i++) {
            final var author = new OrganizationalContact();
            author.setName("author-" + i);

            Component component = new Component();
            component.setProject(project);
            component.setAuthors(List.of(author));
            component.setGroup("component-group");
            component.setName("component-name-" + i);
            component.setVersion(String.valueOf(i) + ".0");
            component.setPurl(new PackageURL(RepositoryType.MAVEN.toString(), "component-group", "component-name-" + i, String.valueOf(i) + ".0", null, null));
            component = qm.createComponent(component, false);
            // direct depencencies
            if (i < 100) {
                // 100 direct depencencies, 900 transitive depencencies
                directDepencencies.add("{\"uuid\":\"" + component.getUuid() + "\"}");
            }
            // Recent & Outdated
            if ((i >= 25) && (i < 225)) {
                // 100 outdated components, 75 of these are direct dependencies, 25 transitive
                packageMetadataList.add(new PackageMetadata(
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        String.valueOf(i + 1) + ".0",
                        null,
                        Instant.now(),
                        null,
                        null));
                artifactMetadataList.add(new PackageArtifactMetadata(
                        component.getPurl(),
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        null, null, null, null, null, null, null, null));
            } else if (i < 500) {
                // 300 recent components, 25 of these are direct dependencies
                packageMetadataList.add(new PackageMetadata(
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        String.valueOf(i) + ".0",
                        null,
                        Instant.now(),
                        null,
                        null));
                artifactMetadataList.add(new PackageArtifactMetadata(
                        component.getPurl(),
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        null, null, null, null, null, null, null, null));
            } else {
                // 500 components with no metadata, all transitive dependencies
            }
        }
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(packageMetadataList));
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(artifactMetadataList));
        project.setDirectDependencies("[" + String.join(",", directDepencencies.toArray(new String[0])) + "]");
        return project;
    }

    protected JsonArray parseJsonArray(Response response) {
        StringReader stringReader = new StringReader(response.readEntity(String.class));
        try (JsonReader jsonReader = Json.createReader(stringReader)) {
            return jsonReader.readArray();
        }
    }
}
