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
package org.dependencytrack.resources.v2;

import com.github.packageurl.PackageURL;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.License;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Scope;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class ProjectsResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    @Test
    public void listProjectComponents() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        var project = prepareProject();

        Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                        "name" : "component-name",
                        "version" : "1.0",
                        "group" : "component-group",
                        "purl" : "pkg:maven/foo/bar@1.0",
                        "internal" : false,
                        "hashes": {
                              "md5": "hash-md5"
                        },
                        "uuid" : "${json-unit.any-string}"
                      }, {
                        "name" : "component-name",
                        "version" : "2.0",
                        "group" : "component-group",
                        "purl" : "pkg:maven/foo/bar@2.0",
                        "internal" : false,
                        "scope": "REQUIRED",
                        "resolved_license" : {
                              "name" : "MIT License",
                              "license_id" : "MIT",
                              "uuid" : "${json-unit.any-string}",
                              "osi_approved" : false,
                              "fsf_libre" : false,
                              "custom_license" : false
                        },
                        "uuid" : "${json-unit.any-string}"
                      }
                  ],
                  "next_page_token": "${json-unit.any-string}",
                  "total": {
                    "count": 3,
                    "type": "EXACT"
                  }
                }
                """);

        final String nextPageToken = responseJson.getString("next_page_token");

        response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("limit", 2)
                .queryParam("page_token", nextPageToken)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items" : [ {
                       "name" : "component-name",
                       "version" : "3.0",
                       "group" : "component-group",
                       "purl" : "pkg:maven/foo/bar@3.0",
                       "internal" : false,
                       "uuid" : "${json-unit.any-string}"
                      }
                  ],
                  "total": {
                    "count": 3,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void shouldFilterProjectComponentsBySearchText() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        final var libA = new Component();
        libA.setProject(project);
        libA.setGroup("org.acme");
        libA.setName("widget-core");
        qm.persist(libA);

        final var libB = new Component();
        libB.setProject(project);
        libB.setGroup("com.example");
        libB.setName("gadget");
        qm.persist(libB);

        final var libC = new Component();
        libC.setProject(project);
        libC.setGroup("com.example");
        libC.setName("WIDGET-ui");
        qm.persist(libC);

        final Response nameMatch = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("q", "widget")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(nameMatch.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(nameMatch)).inPath("$.items[*].name")
                .isArray()
                .containsExactlyInAnyOrder("widget-core", "WIDGET-ui");

        final Response groupMatch = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("q", "ACME")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(groupMatch.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(groupMatch)).inPath("$.items[*].name")
                .isArray()
                .containsExactly("widget-core");
    }

    @Test
    public void listProjectComponentsShouldNotMatchUnderscoreAsWildcard() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        final var literal = new Component();
        literal.setProject(project);
        literal.setName("lib_foo");
        qm.persist(literal);

        final var wildcardMatch = new Component();
        wildcardMatch.setProject(project);
        wildcardMatch.setName("libxfoo");
        qm.persist(wildcardMatch);

        final Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("q", "lib_foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items[*].name")
                .isArray()
                .containsExactly("lib_foo");
    }

    @Test
    public void listProjectComponentsShouldNotMatchPercentAsWildcard() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        final var literal = new Component();
        literal.setProject(project);
        literal.setName("lib%foo");
        qm.persist(literal);

        final var other = new Component();
        other.setProject(project);
        other.setName("libbarfoo");
        qm.persist(other);

        final Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("q", "lib%foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items[*].name")
                .isArray()
                .containsExactly("lib%foo");
    }

    @Test
    public void listProjectComponentsShouldNotDropRowsWhenPagingOverNullSortValues() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        // Create 6 components, the first 3 with non-null group, the last 3 with null group.
        final var expectedNames = new java.util.ArrayList<String>();
        for (int i = 0; i < 3; i++) {
            final var c = new Component();
            c.setProject(project);
            c.setName("c-with-group-" + i);
            c.setGroup("group-" + i);
            qm.persist(c);
            expectedNames.add(c.getName());
        }
        for (int i = 0; i < 3; i++) {
            final var c = new Component();
            c.setProject(project);
            c.setName("c-without-group-" + i);
            qm.persist(c);
            expectedNames.add(c.getName());
        }

        final java.util.List<String> collected = new java.util.ArrayList<>();
        String pageToken = null;
        do {
            var target = jersey.target("/projects/" + project.getUuid() + "/components")
                    .queryParam("sort_by", "group")
                    .queryParam("sort_direction", "ASC")
                    .queryParam("limit", 2);
            if (pageToken != null) {
                target = target.queryParam("page_token", pageToken);
            }
            final Response response = target.request().header(X_API_KEY, apiKey).get();
            assertThat(response.getStatus()).isEqualTo(200);
            final JsonObject body = parseJsonObject(response);
            body.getJsonArray("items").forEach(v ->
                    collected.add(v.asJsonObject().getString("name")));
            pageToken = body.containsKey("next_page_token") ? body.getString("next_page_token") : null;
        } while (pageToken != null);

        assertThat(collected).containsExactlyInAnyOrderElementsOf(expectedNames);
    }

    @Test
    public void listProjectComponentsDescByLastInheritedRiskScoreShouldIncludeNullScores() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        // 4 components with null risk score, 2 with non-null scores.
        final var expectedNames = new java.util.ArrayList<String>();
        for (int i = 0; i < 4; i++) {
            final var c = new Component();
            c.setProject(project);
            c.setName("null-score-" + i);
            qm.persist(c);
            expectedNames.add(c.getName());
        }
        for (int i = 0; i < 2; i++) {
            final var c = new Component();
            c.setProject(project);
            c.setName("score-" + i);
            c.setLastInheritedRiskScore((double) (i + 1));
            qm.persist(c);
            expectedNames.add(c.getName());
        }

        final java.util.List<String> collected = new java.util.ArrayList<>();
        String pageToken = null;
        do {
            var target = jersey.target("/projects/" + project.getUuid() + "/components")
                    .queryParam("sort_by", "last_inherited_risk_score")
                    .queryParam("sort_direction", "DESC")
                    .queryParam("limit", 2);
            if (pageToken != null) {
                target = target.queryParam("page_token", pageToken);
            }
            final Response response = target.request().header(X_API_KEY, apiKey).get();
            assertThat(response.getStatus()).isEqualTo(200);
            final JsonObject body = parseJsonObject(response);
            body.getJsonArray("items").forEach(v ->
                    collected.add(v.asJsonObject().getString("name")));
            pageToken = body.containsKey("next_page_token") ? body.getString("next_page_token") : null;
        } while (pageToken != null);

        assertThat(collected).containsExactlyInAnyOrderElementsOf(expectedNames);
        // DESC NULLS FIRST: all null-score components appear before any scored components.
        final int lastNullIdx = collected.lastIndexOf("null-score-3");
        final int firstScoredIdx = Math.min(collected.indexOf("score-0"), collected.indexOf("score-1"));
        assertThat(firstScoredIdx).isGreaterThan(lastNullIdx);
    }

    @Test
    public void listProjectComponentsSortByPublishedAtAscTest() throws Exception {
        final Project project = preparePublishedAtFixture();
        final Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("limit", 10)
                .queryParam("sort_by", "package_artifact_metadata.published_at")
                .queryParam("sort_direction", "ASC")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items[*].name")
                .isEqualTo(/* language=JSON */ "[\"old\", \"new\", \"unresolved\"]");
    }

    @Test
    public void listProjectComponentsSortByPublishedAtDescTest() throws Exception {
        final Project project = preparePublishedAtFixture();
        final Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("limit", 10)
                .queryParam("sort_by", "package_artifact_metadata.published_at")
                .queryParam("sort_direction", "DESC")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items[*].name")
                .isEqualTo(/* language=JSON */ "[\"new\", \"old\", \"unresolved\"]");
    }

    private Project preparePublishedAtFixture() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("p", null, "1.0", null, null, null, null, false);

        final var compOld = new Component();
        compOld.setProject(project);
        compOld.setName("old");
        compOld.setPurl(new PackageURL("maven", "test", "old", "1.0", null, null));
        qm.createComponent(compOld, false);

        final var compNew = new Component();
        compNew.setProject(project);
        compNew.setName("new");
        compNew.setPurl(new PackageURL("maven", "test", "new", "1.0", null, null));
        qm.createComponent(compNew, false);

        final var compUnresolved = new Component();
        compUnresolved.setProject(project);
        compUnresolved.setName("unresolved");
        compUnresolved.setPurl(new PackageURL("maven", "test", "unresolved", "1.0", null, null));
        qm.createComponent(compUnresolved, false);

        final Instant resolvedAt = Instant.ofEpochMilli(1_700_000_000_000L);
        final var oldPackagePurl = new PackageURL("maven", "test", "old", null, null, null);
        final var newPackagePurl = new PackageURL("maven", "test", "new", null, null, null);
        useJdbiHandle(handle ->
                new PackageMetadataDao(handle).upsertAll(java.util.List.of(
                        new PackageMetadata(oldPackagePurl, null, null, resolvedAt, null, null),
                        new PackageMetadata(newPackagePurl, null, null, resolvedAt, null, null))));
        useJdbiHandle(handle ->
                new PackageArtifactMetadataDao(handle).upsertAll(java.util.List.of(
                        new PackageArtifactMetadata(
                                new PackageURL("maven", "test", "old", "1.0", null, null),
                                oldPackagePurl,
                                null, null, null, null,
                                Instant.ofEpochMilli(1_500_000_000_000L),
                                null, "central", resolvedAt),
                        new PackageArtifactMetadata(
                                new PackageURL("maven", "test", "new", "1.0", null, null),
                                newPackagePurl,
                                null, null, null, null,
                                Instant.ofEpochMilli(1_700_000_000_000L),
                                null, "central", resolvedAt))));
        return project;
    }

    @Test
    public void listProjectComponentsShouldExpandOccurrenceCountTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var occurrenceA = new ComponentOccurrence();
        occurrenceA.setComponent(component);
        occurrenceA.setLocation("/foo/bar/baz");
        qm.persist(occurrenceA);

        final var occurrenceB = new ComponentOccurrence();
        occurrenceB.setComponent(component);
        occurrenceB.setLocation("/foo/qux");
        qm.persist(occurrenceB);

        final Response response = jersey.target("/projects/" + project.getUuid() + "/components")
                .queryParam("expand", "occurrence_count")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).inPath("$.items[*].occurrence_count")
                .isArray()
                .containsExactly(2);
    }

    @Test
    public void listProjectComponentsWithAclEnabledTest() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        // Create project and give access to current principal's team.
        final Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        accessProject.addAccessTeam(team);

        // Create a second project that the current principal has no access to.
        final Project noAccessProject = qm.createProject("acme-app-b", null, "2.0.0", null, null, null, null, false);

        Response response = jersey.target("/projects/" + accessProject.getUuid() + "/components")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assertions.assertEquals(200, response.getStatus(), 0);

        response = jersey.target("/projects/" + noAccessProject.getUuid() + "/components")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assertions.assertEquals(403, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "title" : "Project access denied",
                  "detail" : "Access to the requested project is forbidden",
                  "type" : "about:blank",
                  "status" : 403
                }
                """);
    }

    @Test
    public void listComponentsForProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Response response = jersey.target("/projects/" + UUID.randomUUID() + "/components")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assertions.assertEquals(404, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void cloneProjectShouldReturnUuidOfClonedProject() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).containsOnlyKeys("uuid");

        final String clonedProjectUuid = responseJson.getString("uuid");
        assertThat(response.getLocation()).isNotNull();
        assertThat(response.getLocation().getPath()).endsWith("/projects/" + clonedProjectUuid);

        final Project clonedProject = qm.getObjectByUuid(Project.class, clonedProjectUuid);
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getName()).isEqualTo("acme-app");
        assertThat(clonedProject.getVersion()).isEqualTo("2.0.0");
    }

    @Test
    public void cloneProjectShouldMarkNewProjectAsLatestWhenRequested() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setIsLatest(true);
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0",
                          "version_is_latest": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).containsOnlyKeys("uuid");

        final String clonedProjectUuid = responseJson.getString("uuid");
        assertThat(response.getLocation()).isNotNull();
        assertThat(response.getLocation().getPath()).endsWith("/projects/" + clonedProjectUuid);

        final Project clonedProject = qm.getObjectByUuid(Project.class, clonedProjectUuid);
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getName()).isEqualTo("acme-app");
        assertThat(clonedProject.getVersion()).isEqualTo("2.0.0");
        assertThat(clonedProject.isLatest()).isTrue();

        qm.getPersistenceManager().evictAll(project);
        assertThat(project.isLatest()).isFalse();
    }

    @Test
    public void cloneProjectShouldReturnForbiddenWhenAclIsEnabledAndProjectIsNotAccessible() {
        enablePortfolioAccessControl();

        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);
    }

    @Test
    public void cloneProjectShouldReturnNotFoundWhenProjectDoesNotExist() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Response response = jersey.target("/projects/c5b13f13-f2f0-4a30-97b5-94d164a345f6/clone")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "2.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void cloneProjectShouldReturnConflictWhenNewVersionAlreadyExists() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "1.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 409,
                  "title": "Resource already exists",
                  "detail": "Target project version already exists: 1.0.0"
                }
                """);
    }


    @Test
    public void cloneProjectShouldUpdateMetrics() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Project project = qm.createProject("Example Project 1", "Description 1", "1.0", null, null, null, null, false, false);

        final Component comp = new Component();
        comp.setId(111L);
        comp.setName("name");
        comp.setProject(project);
        comp.setVersion("1.0");
        comp.setCopyright("Copyright Acme");
        qm.createComponent(comp, true);

        final Vulnerability vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);

        qm.addVulnerability(vuln, comp, "INTERNAL_ANALYZER", "Vuln1", "http://vuln.com/vuln1", new Date(1708559165229L));

        final Response response = jersey.target("/projects/%s/clone".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "version": "1.1.0",
                          "includes": ["COMPONENTS", "FINDINGS"]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);

        final String clonedProjectUuid = parseJsonObject(response).getString("uuid");
        final Project clonedProject = qm.getObjectByUuid(Project.class, clonedProjectUuid);
        assertThat(clonedProject).isNotNull();

        final ProjectMetrics metrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getMostRecentProjectMetrics(clonedProject.getId()));
        assertThat(metrics).isNotNull();
        assertThat(metrics.getComponents()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(1);
        assertThat(metrics.getVulnerabilities()).isEqualTo(1);
    }

    private Project prepareProject() {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final var license = new License();
        license.setLicenseId("MIT");
        license.setName("MIT License");
        qm.persist(license);

        Component component = new Component();
        component.setProject(project);
        component.setGroup("component-group");
        component.setName("component-name");
        component.setVersion("1.0");
        component.setPurl("pkg:maven/foo/bar@1.0");
        component.setMd5("hash-md5");
        qm.createComponent(component, false);

        component = new Component();
        component.setProject(project);
        component.setGroup("component-group");
        component.setName("component-name");
        component.setVersion("2.0");
        component.setPurl("pkg:maven/foo/bar@2.0");
        component.setScope(Scope.REQUIRED);
        component.setResolvedLicense(license);
        qm.createComponent(component, false);

        component = new Component();
        component.setProject(project);
        component.setGroup("component-group");
        component.setName("component-name");
        component.setVersion("3.0");
        component.setPurl("pkg:maven/foo/bar@3.0");
        qm.createComponent(component, false);

        return project;
    }
}