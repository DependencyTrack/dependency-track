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
import alpine.model.IConfigProperty.PropertyType;
import alpine.model.ManagedUser;
import alpine.model.Team;
import alpine.server.auth.SessionTokenService;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import alpine.server.resources.GlobalExceptionHandler;
import com.github.packageurl.PackageURL;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyIdentityRow;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

class ProjectResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ProjectResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(GlobalExceptionHandler.class));

    @Test
    void getProjectsDefaultRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(100, json.size());
        Assertions.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals("0", json.getJsonObject(0).getString("version"));
    }

    @Test
    void shouldReturn400WhenSortNameIsNotSupportedForGetProjects() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target(V1_PROJECT)
                .queryParam("sortName", "invalidField")
                .queryParam("sortOrder", "asc")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "type": "/problems/invalid-sort-field",
                          "status": 400,
                          "title": "Invalid sort field",
                          "detail": "Sorting by field 'invalidField' is not supported",
                          "invalidField": "invalidField",
                          "supportedFields": [
                            "group",
                            "name",
                            "version",
                            "classifier",
                            "inactiveSince",
                            "isLatest",
                            "lastBomImport",
                            "lastBomImportFormat",
                            "lastInheritedRiskScore"
                          ]
                        }
                        """);
    }

    @Test
    void shouldReturn400WhenSortNameIsNotSupportedForGetProjectsConcise() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("sortName", "invalidField")
                .queryParam("sortOrder", "asc")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "type": "/problems/invalid-sort-field",
                          "status": 400,
                          "title": "Invalid sort field",
                          "detail": "Sorting by field 'invalidField' is not supported",
                          "invalidField": "invalidField",
                          "supportedFields": [
                            "group",
                            "name",
                            "version",
                            "classifier",
                            "inactiveSince",
                            "isLatest",
                            "lastBomImport",
                            "lastBomImportFormat",
                            "lastRiskScore"
                          ]
                        }
                        """);
    }

    @Test
    void getProjectsWithDataTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        var project = qm.createProject("Acme Example", null, "1.0", null, null, new PackageURL(RepositoryType.MAVEN.toString(), "foo", "acme", "1.0", null, null), null, false);
        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        project.setAuthor("author");
        project.setClassifier(Classifier.APPLICATION);
        project.setDescription("project description");
        project.setExternalReferences(List.of(new ExternalReference()));
        project.setLastBomImport(new Date());
        project.setLastBomImportFormat("projectBomFormat");
        project.setLastInheritedRiskScore(7.7);
        project.setLastVulnerabilityAnalysis(new Date());
        project.setPublisher("projectPublisher");

        final var projectContact = new OrganizationalContact();
        projectContact.setName("supplierContactName");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("supplierName");
        projectSupplier.setUrls(new String[]{"https://supplier.example.com"});
        projectSupplier.setContacts(List.of(projectContact));
        project.setSupplier(projectSupplier);

        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("manufacturerName");
        projectManufacturer.setUrls(new String[]{"https://manufacturer.example.com"});
        projectManufacturer.setContacts(List.of(projectContact));
        project.setManufacturer(projectManufacturer);

        qm.bind(project, List.of(qm.createTag("foo")));

        final var metadataAuthor = new OrganizationalContact();
        metadataAuthor.setName("metadataAuthorName");
        final var metadataSupplier = new OrganizationalEntity();
        metadataSupplier.setName("metadataSupplierName");
        final var metadata = new ProjectMetadata();
        metadata.setProject(project);
        metadata.setAuthors(List.of(metadataAuthor));
        metadata.setSupplier(metadataSupplier);
        qm.persist(metadata);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [ {
                   "publisher" : "projectPublisher",
                   "manufacturer" : {
                     "name" : "manufacturerName",
                     "urls" : [ "https://manufacturer.example.com" ],
                     "contacts" : [ {
                       "name" : "supplierContactName"
                     } ]
                   },
                   "supplier" : {
                     "name" : "supplierName",
                     "urls" : [ "https://supplier.example.com" ],
                     "contacts" : [ {
                       "name" : "supplierContactName"
                     } ]
                   },
                   "name" : "Acme Example",
                   "description" : "project description",
                   "version" : "1.0",
                   "classifier" : "APPLICATION",
                   "purl" : "pkg:maven/foo/acme@1.0",
                   "uuid" : "${json-unit.any-string}",
                   "tags" : [ {
                     "name" : "foo"
                   } ],
                   "lastBomImport" : "${json-unit.any-number}",
                   "lastBomImportFormat" : "projectBomFormat",
                   "lastInheritedRiskScore" : 7.7,
                   "lastVulnerabilityAnalysis" : "${json-unit.any-number}",
                   "externalReferences" : [ { } ],
                   "metadata" : {
                     "supplier" : {
                       "name" : "metadataSupplierName"
                     },
                     "authors" : [ {
                       "name" : "metadataAuthorName"
                     } ]
                   },
                   "isLatest" : false,
                   "active" : true,
                   "hasChildren" : false
                 } ]
                """);
    }

    @Test
        // https://github.com/DependencyTrack/dependency-track/issues/2583
    void getProjectsWithAclEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        // Create project and give access to current principal's team.
        final Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        accessProject.addAccessTeam(team);

        // Create a second project that the current principal has no access to.
        qm.createProject("acme-app-b", null, "2.0.0", null, null, null, null, false);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("acme-app-a", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals("1.0.0", json.getJsonObject(0).getString("version"));
    }

    @Test
    void getProjectsPaginationTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 3; i++) {
            final var project = new Project();
            project.setName("acme-app-" + (i + 1));
            qm.persist(project);
        }

        Response response = jersey.target(V1_PROJECT)
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                      "name" : "acme-app-1",
                      "uuid" : "${json-unit.any-string}",
                      "isLatest" : false,
                      "active" : true,
                      "hasChildren" : false
                    }, {
                      "name" : "acme-app-2",
                      "uuid" : "${json-unit.any-string}",
                      "isLatest" : false,
                      "active" : true,
                      "hasChildren" : false
                  }
                ]
                """);

        response = jersey.target(V1_PROJECT)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                      "name" : "acme-app-3",
                      "uuid" : "${json-unit.any-string}",
                      "isLatest" : false,
                      "active" : true,
                      "hasChildren" : false
                  }
                ]
                """);
    }

    @Test
    void getProjectsByTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.bind(projectB, List.of(qm.createTag("foo")));

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/tag/" + "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/tag/" + "foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                      "name" : "acme-app-b",
                      "uuid" : "${json-unit.any-string}",
                      "tags" : [ {
                        "name" : "foo"
                      } ],
                      "isLatest" : false,
                      "active" : true,
                      "hasChildren" : false
                  }
                ]
                """);
    }

    @Test
    void getProjectsNotAssignedToTeamWithUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        projectB.setAccessTeams(Set.of(team));

        // Should exclude projectB as it is assigned to the team.
        Response response = jersey.target(V1_PROJECT)
                .queryParam("notAssignedToTeamWithUuid", team.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [ {
                   "name" : "acme-app-a",
                   "uuid" : "${json-unit.any-string}",
                   "isLatest" : false,
                   "active" : true,
                   "hasChildren" : false
                 } ]
                """);
    }

    @Test
    void getSingleProjectByNameTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 10; i++) {
            qm.createProject("Acme Example " + i, null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "Acme Example 7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Acme Example 7", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals("7", json.getJsonObject(0).getString("version"));
    }

    @Test
    void getProjectsByNameRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "Acme Example")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(100, json.size());
        Assertions.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals("0", json.getJsonObject(0).getString("version"));
    }

    @Test
    void getProjectsByClassifierRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createProject("Acme Example A", null, "1.0", null, null, null, null, false);
        var p2 = qm.createProject("Acme Example B", null, "1.0", null, null, null, null, false);
        p2.setClassifier(Classifier.LIBRARY);
        Response response = jersey.target(V1_PROJECT + "/classifier/" + Classifier.LIBRARY.name())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Acme Example B", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals("LIBRARY", json.getJsonObject(0).getString("classifier"));
    }

    @Test
    void getProjectsWithMetricsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        var projectMetrics = new ProjectMetrics();
        projectMetrics.setProjectId(project.getId());
        projectMetrics.setLow(10);
        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();
            projectMetrics.setFirstOccurrence(Date.from(dbNow));
            projectMetrics.setLastOccurrence(Date.from(dbNow));
            dao.createProjectMetrics(projectMetrics);
        });
        project.setMetrics(projectMetrics);

        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Acme Example", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals(10, json.getJsonObject(0).getJsonObject("metrics").getInt("low"));
    }

    @Test
    void getProjectsByInvalidNameRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "blah")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(0, json.size());
    }

    @Test
    void getProjectsByNameActiveOnlyRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 500; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        for (int i = 500; i < 1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, new Date(), false);
        }
        Response response = jersey.target(V1_PROJECT)
                .queryParam("name", "Acme Example")
                .queryParam("excludeInactive", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(500), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(100, json.size());
    }

    @Test
    void getProjectsOnlyRootTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setParent(projectA);
        projectB.setName("acme-app-b");
        projectB.setInactiveSince(new Date());
        qm.persist(projectB);

        // Should return both when onlyRoot=false.
        var response = jersey.target(V1_PROJECT)
                .queryParam("onlyRoot", "false")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [ {
                   "name" : "acme-app-a",
                   "uuid" : "${json-unit.any-string}",
                   "isLatest" : false,
                   "active" : true,
                   "hasChildren" : true
                 }, {
                   "parent": {
                     "uuid": "${json-unit.any-string}",
                     "name": "acme-app-a"
                   },
                   "name" : "acme-app-b",
                   "uuid" : "${json-unit.any-string}",
                   "inactiveSince" : "${json-unit.any-number}",
                   "isLatest" : false,
                   "active" : false,
                   "hasChildren" : false
                 } ]
                """);

        // Should return only the parent when onlyRoot=true.
        response = jersey.target(V1_PROJECT)
                .queryParam("onlyRoot", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [ {
                   "name" : "acme-app-a",
                   "uuid" : "${json-unit.any-string}",
                   "isLatest" : false,
                   "active" : true,
                   "hasChildren" : true
                 } ]
                """);
    }

    @Test
    void getProjectLookupTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 500; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, null, false);
        }
        Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "Acme Example")
                .queryParam("version", "10")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Acme Example", json.getString("name"));
        Assertions.assertEquals("10", json.getString("version"));
        Assertions.assertEquals(500, json.getJsonArray("versions").size());
        Assertions.assertNotNull(json.getJsonArray("versions").getJsonObject(100).getString("uuid"));
        Assertions.assertNotEquals("", json.getJsonArray("versions").getJsonObject(100).getString("uuid"));
        Assertions.assertEquals("100", json.getJsonArray("versions").getJsonObject(100).getString("version"));
        Assertions.assertFalse(json.getJsonArray("versions").getJsonObject(100).getBoolean("isLatest"));
    }

    @Test
    void getProjectLookupNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "acme-app")
                .queryParam("version", "3.2.1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The project could not be found.");
    }

    @Test
    void getProjectLookupNotPermittedTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "acme-app")
                .queryParam("version", "1.2.3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);
    }

    @Test
    void getProjectsAscOrderedRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_ASC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    void getProjectsDescOrderedRequestTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT)
                .queryParam(ORDER_BY, "name")
                .queryParam(SORT, SORT_DESC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("DEF", json.getJsonObject(0).getString("name"));
    }

    @Test
    void shouldSortProjectsByLastInheritedRiskScoreIncludingCollectionProjects() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setLastInheritedRiskScore(10.0);
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        projectB.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(projectB, List.of(), false);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        projectC.setParent(projectB);
        projectC.setLastInheritedRiskScore(6.0);
        qm.persist(projectC);

        final var projectD = new Project();
        projectD.setName("acme-app-d");
        projectD.setLastInheritedRiskScore(5.0);
        qm.persist(projectD);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();

            final var childMetrics = new ProjectMetrics();
            childMetrics.setProjectId(projectC.getId());
            childMetrics.setInheritedRiskScore(7.0);
            childMetrics.setFirstOccurrence(Date.from(dbNow));
            childMetrics.setLastOccurrence(Date.from(dbNow));
            testDao.createProjectMetrics(childMetrics);
        });

        final Response response = jersey
                .target(V1_PROJECT)
                .queryParam(ORDER_BY, "lastInheritedRiskScore")
                .queryParam(SORT, SORT_DESC)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("4");

        final JsonArray json = parseJsonArray(response);
        assertThat(json)
                .extracting(value -> ((JsonObject) value).getString("name"))
                .containsExactly(
                        "acme-app-a",
                        "acme-app-b",
                        "acme-app-c",
                        "acme-app-d");
        assertThat(json)
                .extracting(value -> ((JsonObject) value).getJsonNumber("lastInheritedRiskScore").doubleValue())
                .containsExactly(10.0, 7.0, 6.0, 5.0);
    }

    @Test
    void getProjectsConciseTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var project = new Project();
        project.setGroup("com.acme");
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.APPLICATION);
        project.setLastInheritedRiskScore(1.23);
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "group": "com.acme",
                            "name": "acme-app",
                            "version": "1.0.0",
                            "classifier": "APPLICATION",
                            "active": true,
                            "isLatest": false,
                            "tags": [
                              {
                                "name": "foo"
                              }
                            ],
                            "lastRiskScore": 1.23,
                            "hasChildren": false
                          }
                        ]
                        """);
    }

    @Test
    void getProjectsConciseWithAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setInactiveSince(new Date());
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Only grant access to acme-app-a.
        projectA.addAccessTeam(team);

        final Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": false,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));
    }

    @Test
    void getProjectsConciseEmptyTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void getProjectsConcisePaginationTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        for (int i = 0; i < 3; i++) {
            final var project = new Project();
            project.setName("acme-app-" + (i + 1));
            qm.persist(project);
        }

        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-1",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-2",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-3",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectsConciseFilterByNameTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("name", "acme")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("name", "acme-app-b")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectsConciseFilterByVersionTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setVersion("1.0");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        projectB.setVersion("2.0");
        qm.persist(projectB);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("version", "0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("version", "2.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "version": "2.0",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectsConciseFilterByTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        qm.bind(projectB, List.of(qm.createTag("foo")));

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("tag", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("tag", "foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "tags": [
                      {
                        "name": "foo"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectsConciseFilterByTeamTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();
        // Create project and give access to current principal's team.
        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        projectB.addAccessTeam(team);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("team", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("team", team.getName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));
    }

    @Test
    void getProjectsConciseOnlyRootTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setParent(projectA);
        projectB.setName("acme-app-b");
        projectB.setInactiveSince(new Date());
        qm.persist(projectB);

        // Should return both when onlyRoot is not set at all.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": true
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should return both when onlyRoot=false.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("onlyRoot", "false")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": true
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should return only the parent when onlyRoot=true.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("onlyRoot", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": true
                  }
                ]
                """);
    }

    @Test
    void getProjectsConciseWithFilterByActiveTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setInactiveSince(new Date());
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Should return both when active is not set or active is false.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-a",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should return only active when active=true
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("active", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectsConciseWithLatestMetricsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday.minusDays(1));
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();
            final Instant projectMetricsOldOccurrence = dbNow.minus(1, ChronoUnit.HOURS);
            final Instant projectMetricsLatestOccurrence = dbNow.minus(5, ChronoUnit.MINUTES);

            final var projectMetricsOld = new ProjectMetrics();
            projectMetricsOld.setProjectId(project.getId());
            projectMetricsOld.setCritical(666);
            projectMetricsOld.setFirstOccurrence(Date.from(projectMetricsOldOccurrence));
            projectMetricsOld.setLastOccurrence(Date.from(projectMetricsOldOccurrence));
            dao.createProjectMetrics(projectMetricsOld);

            final var projectMetricsLatest = new ProjectMetrics();
            projectMetricsLatest.setProjectId(project.getId());
            projectMetricsLatest.setComponents(1);
            projectMetricsLatest.setCritical(2);
            projectMetricsLatest.setHigh(3);
            projectMetricsLatest.setLow(4);
            projectMetricsLatest.setMedium(5);
            projectMetricsLatest.setPolicyViolationsFail(6);
            projectMetricsLatest.setPolicyViolationsInfo(7);
            projectMetricsLatest.setPolicyViolationsLicenseTotal(8);
            projectMetricsLatest.setPolicyViolationsOperationalTotal(9);
            projectMetricsLatest.setPolicyViolationsSecurityTotal(10);
            projectMetricsLatest.setPolicyViolationsTotal(11);
            projectMetricsLatest.setPolicyViolationsWarn(12);
            projectMetricsLatest.setInheritedRiskScore(13.13);
            projectMetricsLatest.setUnassigned(14);
            projectMetricsLatest.setVulnerabilities(15);
            projectMetricsLatest.setFirstOccurrence(Date.from(projectMetricsLatestOccurrence));
            projectMetricsLatest.setLastOccurrence(Date.from(projectMetricsLatestOccurrence));
            dao.createProjectMetrics(projectMetricsLatest);
        });

        // Should not include metrics if not explicitly requested.
        Response response = jersey.target(V1_PROJECT + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should include metrics when explicitly requested.
        response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false,
                    "metrics": {
                      "components": 1,
                      "critical": 2,
                      "high": 3,
                      "low": 4,
                      "medium": 5,
                      "policyViolationsFail": 6,
                      "policyViolationsInfo": 7,
                      "policyViolationsLicenseTotal": 8,
                      "policyViolationsOperationalTotal": 9,
                      "policyViolationsSecurityTotal": 10,
                      "policyViolationsTotal": 11,
                      "policyViolationsWarn": 12,
                      "inheritedRiskScore": 13.13,
                      "unassigned": 14,
                      "vulnerabilities": 15
                    }
                  }
                ]
                """);
    }

    @Test
    void getProjectChildrenConciseTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setGroup("com.acme");
        parentProject.setName("acme-app");
        parentProject.setVersion("1.0.0");
        parentProject.setClassifier(Classifier.APPLICATION);
        qm.persist(parentProject);

        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setGroup("com.acme");
        childProject.setName("acme-child-app");
        childProject.setVersion("2.0.0");
        childProject.setClassifier(Classifier.APPLICATION);
        qm.persist(childProject);

        qm.bind(childProject, List.of(qm.createTag("foo")));

        final Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("childProjectUuid", equalTo(childProject.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:childProjectUuid}",
                            "group": "com.acme",
                            "name": "acme-child-app",
                            "version": "2.0.0",
                            "classifier": "APPLICATION",
                            "active": true,
                            "isLatest": false,
                            "tags": [
                              {
                                "name": "foo"
                              }
                            ],
                            "hasChildren": false
                          }
                        ]
                        """);
    }

    @Test
    void getProjectChildrenConciseWithAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        qm.persist(childProjectB);

        // Only grant access to acme-app.
        parentProject.addAccessTeam(team);

        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "active": true,
                    "hasChildren": false,
                    "isLatest": false,
                    "name": "acme-child-app-a",
                    "uuid": "${json-unit.any-string}"
                  },
                  {
                    "active": true,
                    "hasChildren": false,
                    "isLatest": false,
                    "name": "acme-child-app-b",
                    "uuid": "${json-unit.any-string}"
                  }
                ]
                """);

        // Additionally grant access to acme-child-app-a.
        childProjectA.addAccessTeam(team);

        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-a",
                    "active": true,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));

        // Revoke access from acme-app.
        parentProject.setAccessTeams(null);

        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void getProjectChildrenConciseEmptyTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void getProjectChildrenConciseWithParentNotExistsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Response response = jersey.target(V1_PROJECT + "/concise/6ce40fad-0cff-427a-86ce-acb248872b5b/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void getProjectChildrenConcisePaginationTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        for (int i = 0; i < 3; i++) {
            final var childProject = new Project();
            childProject.setParent(parentProject);
            childProject.setName("acme-child-app-" + (i + 1));
            qm.persist(childProject);
        }

        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-1",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  },
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-2",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-3",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectChildrenConciseFilterByNameTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        childProjectB.setInactiveSince(new Date());
        qm.persist(childProjectB);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("name", "acme")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("name", "acme-child-app-b")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": false,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectChildrenConciseFilterByVersionTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        childProjectA.setVersion("1.0");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        childProjectB.setVersion("2.0");
        qm.persist(childProjectB);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("version", "0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("version", "1.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-a",
                    "version": "1.0",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectChildrenConciseFilterByTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        qm.persist(childProjectB);

        qm.bind(childProjectB, List.of(qm.createTag("foo")));

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("tag", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("tag", "foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": true,
                    "isLatest": false,
                    "tags": [
                      {
                        "name": "foo"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void getProjectChildrenConciseFilterByTeamTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProjectA = new Project();
        childProjectA.setParent(parentProject);
        childProjectA.setName("acme-child-app-a");
        qm.persist(childProjectA);

        final var childProjectB = new Project();
        childProjectB.setParent(parentProject);
        childProjectB.setName("acme-child-app-b");
        qm.persist(childProjectB);

        childProjectB.addAccessTeam(team);

        // Should not return results for partial matches.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("team", "f")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");

        // Should return results for exact matches.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("team", team.getName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app-b",
                    "active": true,
                    "isLatest": false,
                    "teams": [
                      {
                        "name": "%s"
                      }
                    ],
                    "hasChildren": false
                  }
                ]
                """.formatted(team.getName()));
    }

    @Test
    void getProjectChildrenConciseWithLatestMetricsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app");
        qm.persist(parentProject);

        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-child-app");
        qm.persist(childProject);

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday.minusDays(1));
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();
            final Instant projectMetricsOldOccurrence = dbNow.minus(1, ChronoUnit.HOURS);
            final Instant projectMetricsLatestOccurrence = dbNow.minus(5, ChronoUnit.MINUTES);

            final var projectMetricsOld = new ProjectMetrics();
            projectMetricsOld.setProjectId(childProject.getId());
            projectMetricsOld.setCritical(666);
            projectMetricsOld.setFirstOccurrence(Date.from(projectMetricsOldOccurrence));
            projectMetricsOld.setLastOccurrence(Date.from(projectMetricsOldOccurrence));
            dao.createProjectMetrics(projectMetricsOld);

            final var projectMetricsLatest = new ProjectMetrics();
            projectMetricsLatest.setProjectId(childProject.getId());
            projectMetricsLatest.setComponents(1);
            projectMetricsLatest.setCritical(2);
            projectMetricsLatest.setHigh(3);
            projectMetricsLatest.setLow(4);
            projectMetricsLatest.setMedium(5);
            projectMetricsLatest.setPolicyViolationsFail(6);
            projectMetricsLatest.setPolicyViolationsInfo(7);
            projectMetricsLatest.setPolicyViolationsLicenseTotal(8);
            projectMetricsLatest.setPolicyViolationsOperationalTotal(9);
            projectMetricsLatest.setPolicyViolationsSecurityTotal(10);
            projectMetricsLatest.setPolicyViolationsTotal(11);
            projectMetricsLatest.setPolicyViolationsWarn(12);
            projectMetricsLatest.setInheritedRiskScore(13.13);
            projectMetricsLatest.setUnassigned(14);
            projectMetricsLatest.setVulnerabilities(15);
            projectMetricsLatest.setFirstOccurrence(Date.from(projectMetricsLatestOccurrence));
            projectMetricsLatest.setLastOccurrence(Date.from(projectMetricsLatestOccurrence));
            dao.createProjectMetrics(projectMetricsLatest);
        });

        // Should not include metrics if not explicitly requested.
        Response response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false
                  }
                ]
                """);

        // Should include metrics when explicitly requested.
        response = jersey.target(V1_PROJECT + "/concise/" + parentProject.getUuid() + "/children")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                [
                  {
                    "uuid": "${json-unit.any-string}",
                    "name": "acme-child-app",
                    "active": true,
                    "isLatest": false,
                    "hasChildren": false,
                    "metrics": {
                      "components": 1,
                      "critical": 2,
                      "high": 3,
                      "low": 4,
                      "medium": 5,
                      "policyViolationsFail": 6,
                      "policyViolationsInfo": 7,
                      "policyViolationsLicenseTotal": 8,
                      "policyViolationsOperationalTotal": 9,
                      "policyViolationsSecurityTotal": 10,
                      "policyViolationsTotal": 11,
                      "policyViolationsWarn": 12,
                      "inheritedRiskScore": 13.13,
                      "unassigned": 14,
                      "vulnerabilities": 15
                    }
                  }
                ]
                """);
    }

    @Test
    void getProjectByUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        parentProject.setVersion("1.0.0");
        qm.persist(parentProject);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setParent(parentProject);
        qm.persist(project);

        final var childProject = new Project();
        childProject.setName("acme-app-child");
        childProject.setVersion("1.0.0");
        childProject.setParent(project);
        childProject.setInactiveSince(new Date());
        qm.persist(childProject);

        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("parentUuid", equalTo(parentProject.getUuid().toString()))
                .withMatcher("childUuid", equalTo(childProject.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "version": "1.0.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "parent": {
                            "name": "acme-app-parent",
                            "version": "1.0.0",
                            "uuid": "${json-unit.matches:parentUuid}"
                          },
                          "children": [
                            {
                              "name": "acme-app-child",
                              "version": "1.0.0",
                              "uuid": "${json-unit.matches:childUuid}",
                              "isLatest": false,
                              "active": false,
                              "inactiveSince": "${json-unit.any-number}"
                            }
                          ],
                          "tags": [],
                          "isLatest": false,
                          "active":true,
                          "versions": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "version": "1.0.0",
                              "isLatest": false,
                              "active": true
                            }
                          ]
                        }
                        """);
    }

    @Test
    void getProjectByUuidWithCollectionTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        project.setCollectionTag(qm.createTag("foo"));
        qm.persist(project);

        final Response response = jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "version": "1.0.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "children": [],
                          "tags": [],
                          "isLatest": false,
                          "active":true,
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
                          "collectionTag": {
                            "name": "foo"
                          },
                          "versions": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "version": "1.0.0",
                              "isLatest": false,
                              "active": true
                            }
                          ]
                        }
                        """);
    }

    @Test
    void getProjectByUuidNotPermittedTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);
    }

    @Test
    void getProjectByInvalidUuidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void getProjectByTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("production");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/tag/" + "production")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    void getProjectByCaseInsensitiveTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("PRODUCTION");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/tag/" + "production")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    void getProjectByUnknownTagTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        List<Tag> tags = new ArrayList<>();
        Tag tag = qm.createTag("production");
        tags.add(tag);
        qm.createProject("ABC", null, "1.0", tags, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/tag/" + "stable")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(0), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(0, json.size());
    }

    @Test
    void getProjectsByTagAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("acme-app-accessible");
        accessibleProject.addAccessTeam(super.team);
        qm.persist(accessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final Tag tag = new Tag("foo");
        qm.persist(tag);

        qm.bind(accessibleProject, List.of(tag));
        qm.bind(inaccessibleProject, List.of(tag));

        final Response response = jersey.target(V1_PROJECT + "/tag/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        final String responseJson = getPlainTextBody(response);
        assertThatJson(responseJson).isArray().hasSize(1);
        assertThatJson(responseJson).inPath("$[0].uuid").isEqualTo(accessibleProject.getUuid().toString());
    }

    @Test
    void createProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Acme Example",
                          "version": "1.0",
                          "description": "Test project",
                          "tags": [
                            {
                              "name": "foo"
                            }
                          ]
                        }
                        """));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Acme Example", json.getString("name"));
        Assertions.assertEquals("1.0", json.getString("version"));
        Assertions.assertEquals("Test project", json.getString("description"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThatJson(json.getJsonArray("tags").toString()).isEqualTo("""
                [
                  {
                    "name": "foo"
                  }
                ]
                """);

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification).isNotNull();
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_CREATED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Project Added");
        });
    }

    @Test
    void createProjectDuplicateTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A project with the specified name already exists.", body);
    }

    @Test
    void createProjectInactiveParentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        parentProject.setVersion("1.0.0");
        parentProject.setInactiveSince(new Date());
        qm.persist(parentProject);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "parent": {
                            "uuid": "%s"
                          },
                          "name": "acme-app",
                          "version": "1.2.3"
                        }
                        """.formatted(parentProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("An inactive Parent cannot be selected as parent");
    }

    @ParameterizedTest
    @MethodSource("projectValidationTestData")
    void createProjectValidationTest(String testCase, String json, String expectedError) {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(json));
        Assertions.assertEquals(400, response.getStatus(), "Test case: " + testCase);
        Assertions.assertEquals(expectedError, parseJsonArray(response).getJsonObject(0).getString("message"), "Test case: " + testCase);
    }

    static Stream<Arguments> projectValidationTestData() {
        return Stream.of(Arguments.of("Blank name", "{\"name\": \" \"}", "must not be blank"),
                Arguments.of("Too long description", "{\"name\": \"Valid Project Name\", \"description\": \"" + "a".repeat(256) + "\"}", "size must be between 0 and 255"));
    }

    @Test
    void createProjectNonExistentParentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": "5e506116-8d58-4403-8631-971ec31961f6"
                          },
                          "name": "acme-app"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Parent project could not be found"
                }
                """);
    }

    @Test
    void shouldReturnBadRequestWhenCreatingProjectWithNullParentUuid() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": null
                          },
                          "name": "acme-app"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("parent.uuid must be provided when parent is set");
    }

    @Test
    void createProjectInaccessibleParentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": "%s"
                          },
                          "name": "acme-app"
                        }
                        """.formatted(parentProject.getUuid())));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested parent project is forbidden"
                }
                """);

        parentProject.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(201);
    }

    @Test
    void updateProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        project.setDescription("Test project");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getString("name"));
        Assertions.assertEquals("1.0", json.getString("version"));
        Assertions.assertEquals("Test project", json.getString("description"));
    }

    @Test
    void updateProjectNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        {
                          "uuid": "317fe231-01a4-4435-92ad-abd01017bb1a",
                          "name": "acme-app",
                          "version": "1.2.3"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the project could not be found.");
    }

    @Test
    void updateProjectNotPermittedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "acme-app-foo"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);
    }

    @Test
    void updateProjectTagsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);

        final var jsonProject = new Project();
        jsonProject.setUuid(p1.getUuid());
        jsonProject.setName(p1.getName());
        jsonProject.setVersion(p1.getVersion());
        jsonProject.setTags(Stream.of("tag1", "tag2", "tag3").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toSet()));

        // update the 1st time and add another tag
        var response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        var json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(p1.getName(), json.getString("name"));
        Assertions.assertEquals(p1.getVersion(), json.getString("version"));
        Assertions.assertFalse(json.containsKey("description"));
        var jsonTags = json.getJsonArray("tags");
        Assertions.assertEquals(3, jsonTags.size());
        Assertions.assertEquals("tag1", jsonTags.get(0).asJsonObject().getString("name"));
        Assertions.assertEquals("tag2", jsonTags.get(1).asJsonObject().getString("name"));
        Assertions.assertEquals("tag3", jsonTags.get(2).asJsonObject().getString("name"));

        // and update again with the same tags ... issue #1165
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        json = parseJsonObject(response);
        jsonTags = json.getJsonArray("tags");
        Assertions.assertEquals(3, jsonTags.size());
        Assertions.assertEquals("tag1", jsonTags.get(0).asJsonObject().getString("name"));
        Assertions.assertEquals("tag2", jsonTags.get(1).asJsonObject().getString("name"));
        Assertions.assertEquals("tag3", jsonTags.get(2).asJsonObject().getString("name"));

        // and finally delete one of the tags
        jsonProject.getTags().removeIf(tag -> "tag1".equals(tag.getName()));
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        json = parseJsonObject(response);
        jsonTags = json.getJsonArray("tags");
        Assertions.assertEquals(2, jsonTags.size());
        Assertions.assertEquals("tag2", jsonTags.get(0).asJsonObject().getString("name"));
        Assertions.assertEquals("tag3", jsonTags.get(1).asJsonObject().getString("name"));
    }

    @Test
    void updateProjectEmptyNameTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        project.setName(" ");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    void updateProjectDuplicateTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project project = qm.createProject("DEF", null, "1.0", null, null, null, null, false);
        project = qm.detach(Project.class, project.getId());
        project.setName("ABC");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A project with the specified name and version already exists.", body);
    }

    @Test
    void updateProjectInaccessibleParentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": "%s"
                          },
                          "uuid": "%s",
                          "name": "acme-app"
                        }
                        """.formatted(parentProject.getUuid(), project.getUuid())));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested parent project is forbidden"
                }
                """);

        parentProject.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void updateProjectNonExistentParentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": "b99bd9cf-d8d1-48ae-972e-615e6cc59e52"
                          },
                          "uuid": "%s",
                          "name": "acme-app"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Parent project could not be found"
                }
                """);
    }

    @Test
    void shouldReturnBadRequestWhenUpdatingProjectWithNullParentUuid() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": null
                          },
                          "uuid": "%s",
                          "name": "acme-app"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("parent.uuid must be provided when parent is set");
    }

    @Test
    void deleteProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void deleteProjectInvalidUuidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void deleteProjectAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
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
    void shouldBatchDeleteExistingAndAccessibleProjects() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("acme-app-a");
        accessibleProject.addAccessTeam(super.team);
        qm.persist(accessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-b");
        qm.persist(inaccessibleProject);

        final Response response = jersey
                .target(V1_PROJECT + "/batchDelete")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("""
                        [
                          "%s",
                          "%s",
                          "7638dd9a-a4ca-4cd6-98cc-10386bf0f2d6"
                        ]
                        """.formatted(accessibleProject.getUuid(), inaccessibleProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(204);

        assertThat(qm.doesProjectExist("acme-app-a", null)).isFalse();
        assertThat(qm.doesProjectExist("acme-app-b", null)).isTrue();
    }

    @Test
    void patchProjectNotModifiedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);

        final var jsonProject = new Project();
        jsonProject.setDescription(p1.getDescription());
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assertions.assertEquals(Response.Status.NOT_MODIFIED.getStatusCode(), response.getStatus());
        Assertions.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    void patchProjectNameVersionConflictTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);
        qm.createProject("ABC", "Test project", "0.9", null, null, null, null, false);
        final var jsonProject = new Project();
        jsonProject.setVersion("0.9");
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assertions.assertEquals(Response.Status.CONFLICT.getStatusCode(), response.getStatus());
        Assertions.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    void patchProjectNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(new Project()));
        Assertions.assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
    }

    @Test
    void patchProjectNotPermittedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app-foo"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);
    }

    @Test
    void patchProjectParentTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project project = qm.createProject("DEF", null, "2.0", null, parent, null, null, false);
        final Project newParent = qm.createProject("GHI", null, "3.0", null, null, null, null, false);

        final JsonObject jsonProject = Json.createObjectBuilder()
                .add("parent", Json.createObjectBuilder()
                        .add("uuid", newParent.getUuid().toString()))
                .build();

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject.toString()));

        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", CoreMatchers.equalTo(project.getUuid().toString()))
                .withMatcher("parentProjectUuid", CoreMatchers.equalTo(newParent.getUuid().toString()))
                .isEqualTo("""
                        {
                          "name": "DEF",
                          "version": "2.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "parent": {
                            "name": "GHI",
                            "version": "3.0",
                            "uuid": "${json-unit.matches:parentProjectUuid}"
                          },
                          "tags": [],
                          "isLatest": false,
                          "active": true
                        }
                        """);

        // Ensure the parent was updated.
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getParent()).isNotNull();
        assertThat(project.getParent().getUuid()).isEqualTo(newParent.getUuid());
    }

    @Test
    void patchProjectExternalReferencesTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var project = qm.createProject("referred-project", "ExtRef test project", "1.0", null, null, null, null, false);
        final var ref1 = new ExternalReference();
        ref1.setType(org.cyclonedx.model.ExternalReference.Type.VCS);
        ref1.setUrl("https://github.com/DependencyTrack/awesomeness");
        final var ref2 = new ExternalReference();
        ref2.setType(org.cyclonedx.model.ExternalReference.Type.WEBSITE);
        ref2.setUrl("https://dependencytrack.org");
        ref2.setComment("Worth a visit!");
        final var externalReferences = List.of(ref1, ref2);
        final var jsonProject = new Project();
        jsonProject.setExternalReferences(externalReferences);

        final var response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));

        Assertions.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        final var json = parseJsonObject(response);
        final var patchedExternalReferences = json.getJsonArray("externalReferences");
        Assertions.assertEquals(2, patchedExternalReferences.size());
        final var patchedRef1 = patchedExternalReferences.getJsonObject(0);
        final var patchedRef2 = patchedExternalReferences.getJsonObject(1);
        Assertions.assertEquals("vcs", patchedRef1.getString("type"));
        Assertions.assertEquals("https://github.com/DependencyTrack/awesomeness", patchedRef1.getString("url"));
        Assertions.assertEquals("website", patchedRef2.getString("type"));
        Assertions.assertEquals("https://dependencytrack.org", patchedRef2.getString("url"));
        Assertions.assertEquals("Worth a visit!", patchedRef2.getString("comment"));
    }

    @Test
    void patchProjectParentNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project project = qm.createProject("DEF", null, "2.0", null, parent, null, null, false);

        final JsonObject jsonProject = Json.createObjectBuilder()
                .add("parent", Json.createObjectBuilder()
                        .add("uuid", UUID.randomUUID().toString()))
                .build();

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
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
    void shouldReturnBadRequestWhenPatchingProjectWithNullParentUuid() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final Project project = qm.createProject("DEF", null, "2.0", null, null, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": null
                          }
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("parent.uuid must be provided when parent is set");
    }

    @Test
    void patchProjectParentInaccessibleTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        final var project = new Project();
        project.setName("acme-app");
        project.addAccessTeam(super.team);
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(/* language=JSON */ """
                        {
                          "parent": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(parentProject.getUuid())));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested parent project is forbidden"
                }
                """);
    }

    @Test
    void patchProjectSuccessfullyPatchedTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        final var tags = Stream.of("tag1", "tag2").map(qm::createTag).collect(Collectors.toUnmodifiableList());
        final var p1 = qm.createProject("ABC", "Test project", "1.0", tags, null, null, null, false);
        final var projectManufacturerContact = new OrganizationalContact();
        projectManufacturerContact.setName("manufacturerContactName");
        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("manufacturerName");
        projectManufacturer.setUrls(new String[]{"https://manufacturer.example.com"});
        projectManufacturer.setContacts(List.of(projectManufacturerContact));
        p1.setManufacturer(projectManufacturer);
        final var projectSupplierContact = new OrganizationalContact();
        projectSupplierContact.setName("supplierContactName");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("supplierName");
        projectSupplier.setUrls(new String[]{"https://supplier.example.com"});
        projectSupplier.setContacts(List.of(projectSupplierContact));
        p1.setSupplier(projectSupplier);
        qm.persist(p1);
        final var jsonProject = new Project();
        jsonProject.setInactiveSince(null);
        jsonProject.setName("new name");
        jsonProject.setPublisher("new publisher");
        jsonProject.setTags(Stream.of("tag4").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toSet()));
        final var jsonProjectManufacturerContact = new OrganizationalContact();
        jsonProjectManufacturerContact.setName("newManufacturerContactName");
        final var jsonProjectManufacturer = new OrganizationalEntity();
        jsonProjectManufacturer.setName("manufacturerName");
        jsonProjectManufacturer.setUrls(new String[]{"https://manufacturer.example.com"});
        jsonProjectManufacturer.setContacts(List.of(jsonProjectManufacturerContact));
        jsonProject.setManufacturer(jsonProjectManufacturer);
        final var jsonProjectSupplierContact = new OrganizationalContact();
        jsonProjectSupplierContact.setName("newSupplierContactName");
        final var jsonProjectSupplier = new OrganizationalEntity();
        jsonProjectSupplier.setName("supplierName");
        jsonProjectSupplier.setUrls(new String[]{"https://supplier.example.com"});
        jsonProjectSupplier.setContacts(List.of(jsonProjectSupplierContact));
        jsonProject.setSupplier(jsonProjectSupplier);
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assertions.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertThatJson(getPlainTextBody(response))
                .withMatcher("projectUuid", equalTo(p1.getUuid().toString()))
                .isEqualTo("""
                        {
                          "publisher": "new publisher",
                          "manufacturer": {
                            "name": "manufacturerName",
                            "urls": [
                              "https://manufacturer.example.com"
                            ],
                            "contacts": [
                              {
                                "name": "newManufacturerContactName"
                              }
                            ]
                          },
                          "supplier": {
                            "name": "supplierName",
                            "urls": [
                              "https://supplier.example.com"
                            ],
                            "contacts": [
                              {
                                "name": "newSupplierContactName"
                              }
                            ]
                          },
                          "name": "new name",
                          "description": "Test project",
                          "version": "1.0",
                          "uuid": "${json-unit.matches:projectUuid}",
                          "tags": [
                            {
                              "name": "tag4"
                            }
                          ],
                          "isLatest": false,
                          "active":true,
                          "children": []
                        }
                        """);
    }

    @Test
    void getRootProjectsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);
        qm.createProject("GHI", null, "1.0", null, child, null, null, false);
        Response response = jersey.target(V1_PROJECT)
                .queryParam("onlyRoot", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getJsonObject(0).getString("name"));
        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> json.getJsonObject(1));
    }

    @Test
    void shouldListChildrenProjects() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);
        qm.createProject("GHI", null, "1.0", null, parent, null, null, false);
        qm.createProject("JKL", null, "1.0", null, child, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/" + parent.getUuid().toString() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "name": "DEF",
                    "version": "1.0",
                    "uuid": "${json-unit.any-string}",
                    "isLatest": false,
                    "active": true,
                    "parent": {
                      "uuid": "${json-unit.any-string}",
                      "name": "ABC",
                      "version": "1.0"
                    },
                    "hasChildren": true
                  },
                  {
                    "name": "GHI",
                    "version": "1.0",
                    "uuid": "${json-unit.any-string}",
                    "isLatest": false,
                    "active": true,
                    "parent": {
                      "uuid": "${json-unit.any-string}",
                      "name": "ABC",
                      "version": "1.0"
                    },
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void shouldReturn404WhenGettingChildrenOfUnknownProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey
                .target(V1_PROJECT + "/" + UUID.randomUUID() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn403WhenGettingChildrenOfInaccessibleProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/" + parent.getUuid() + "/children")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldListChildrenProjectsByClassifier() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project library = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);
        library.setClassifier(Classifier.LIBRARY);
        final Project application = qm.createProject("GHI", null, "1.0", null, parent, null, null, false);
        application.setClassifier(Classifier.APPLICATION);

        final Response response = jersey
                .target(V1_PROJECT + "/" + parent.getUuid() + "/children/classifier/" + Classifier.LIBRARY)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "name": "DEF",
                    "version": "1.0",
                    "classifier": "LIBRARY",
                    "uuid": "${json-unit.any-string}",
                    "isLatest": false,
                    "active": true,
                    "parent": {
                      "uuid": "${json-unit.any-string}",
                      "name": "ABC",
                      "version": "1.0"
                    },
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void shouldListChildrenProjectsByTag() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project tagged = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);
        qm.bind(tagged, List.of(qm.createTag("foo")));
        qm.createProject("GHI", null, "1.0", null, parent, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/" + parent.getUuid() + "/children/tag/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "name": "DEF",
                    "version": "1.0",
                    "uuid": "${json-unit.any-string}",
                    "isLatest": false,
                    "active": true,
                    "parent": {
                      "uuid": "${json-unit.any-string}",
                      "name": "ABC",
                      "version": "1.0"
                    },
                    "tags": [
                      { "name": "foo" }
                    ],
                    "hasChildren": false
                  }
                ]
                """);
    }

    @Test
    void shouldReturnEmptyChildrenListForUnknownTag() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, parent, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/" + parent.getUuid() + "/children/tag/does-not-exist")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void updateChildAsParentOfChild() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, null, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setInactiveSince(null);

        tmpProject.setParent(child);
        Assertions.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    void updateParentToInactiveWithActiveChild() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("DEF", null, "1.0", null, parent, null, null, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setInactiveSince(new Date());

        Assertions.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    void createProjectWithoutVersionDuplicateTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = new Project();
        project.setName("Acme Example");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A project with the specified name already exists.", body);
    }

    @Test
    void updateProjectParentToSelf() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);

        Project tmpProject = new Project();
        tmpProject.setName(parent.getName());
        tmpProject.setVersion(parent.getVersion());
        tmpProject.setUuid(parent.getUuid());
        tmpProject.setInactiveSince(parent.getInactiveSince());
        tmpProject.setParent(parent);

        Assertions.assertThrows(IllegalArgumentException.class, () -> qm.updateProject(tmpProject, true));
    }

    @Test
    void shouldListProjectsWithoutDescendantsOf() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project grandParent = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        final Project parent = qm.createProject("DEF", null, "1.0", null, grandParent, null, null, false);
        final Project child = qm.createProject("GHI", null, "1.0", null, parent, null, null, false);
        qm.createProject("JKL", null, "1.0", null, child, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/withoutDescendantsOf/" + parent.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "name": "ABC",
                    "version": "1.0",
                    "uuid": "${json-unit.any-string}",
                    "isLatest": false,
                    "active": true,
                    "hasChildren": true
                  }
                ]
                """);
    }

    @Test
    void shouldReturn404WhenGettingProjectsWithoutDescendantsOfUnknownProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey
                .target(V1_PROJECT + "/withoutDescendantsOf/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn403WhenGettingProjectsWithoutDescendantsOfInaccessibleProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final Project root = qm.createProject("ABC", null, "1.0", null, null, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/withoutDescendantsOf/" + root.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void cloneProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("projectManufacturer");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("projectSupplier");

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setManufacturer(projectManufacturer);
        project.setSupplier(projectSupplier);
        project.setAccessTeams(Set.of(team));
        qm.persist(project);

        final ProjectProperty projectProperty = qm.createProjectProperty(project, "group", "name", "value", PropertyType.STRING, "description");

        qm.bind(project, List.of(
                qm.createTag("tag-a"),
                qm.createTag("tag-b")
        ));

        final var metadataAuthor = new OrganizationalContact();
        metadataAuthor.setName("metadataAuthor");
        final var metadataSupplier = new OrganizationalEntity();
        metadataSupplier.setName("metadataSupplier");
        final var metadata = new ProjectMetadata();
        metadata.setProject(project);
        metadata.setAuthors(List.of(metadataAuthor));
        metadata.setSupplier(metadataSupplier);
        qm.persist(metadata);

        final var componentSupplier = new OrganizationalEntity();
        componentSupplier.setName("componentSupplier");

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("2.0.0");
        componentA.setSwidTagId("swidTagId");
        componentA.setSupplier(componentSupplier);
        qm.persist(componentA);

        final var componentOccurrence = new ComponentOccurrence();
        componentOccurrence.setComponent(componentA);
        componentOccurrence.setLocation("location");
        componentOccurrence.setLine(666);
        componentOccurrence.setOffset(123);
        componentOccurrence.setSymbol("symbol");
        qm.persist(componentOccurrence);

        final var componentProperty = new ComponentProperty();
        componentProperty.setComponent(componentA);
        componentProperty.setGroupName("groupName");
        componentProperty.setPropertyName("propertyName");
        componentProperty.setPropertyValue("propertyValue");
        componentProperty.setPropertyType(PropertyType.STRING);
        qm.persist(componentProperty);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("2.1.0");
        qm.persist(componentB);

        final var service = new ServiceComponent();
        service.setProject(project);
        service.setName("acme-service");
        service.setVersion("3.0.0");
        qm.persist(service);

        project.setDirectDependencies(Mappers.jsonMapper().createArrayNode().add(new ComponentIdentity(componentA).toJSON()).toString());
        componentA.setDirectDependencies(Mappers.jsonMapper().createArrayNode().add(new ComponentIdentity(componentB).toJSON()).toString());

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.addVulnerability(vuln, componentA, "internal");

        final long analysisId = qm.makeAnalysis(
                new MakeAnalysisCommand(componentA, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.REQUIRES_ENVIRONMENT)
                        .withResponse(AnalysisResponse.WILL_NOT_FIX)
                        .withDetails("details")
                        .withCommenter("commenter")
                        .withComment("comment"));

        final VulnPolicyIdentityRow vulnPolicy = withJdbiHandle(handle -> {
            final var policyAnalysis = new VulnerabilityPolicyAnalysis();
            policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.EXPLOITABLE);

            final var policy = new VulnerabilityPolicy();
            policy.setName("foo");
            policy.setAnalysis(policyAnalysis);
            policy.setCondition("true");
            return handle.attach(VulnerabilityPolicyDao.class).create(policy);
        });
        useJdbiHandle(handle -> handle.createUpdate("""
                        WITH "VULN_POLICY" AS (
                          SELECT "ID"
                            FROM "VULNERABILITY_POLICY"
                           WHERE "NAME" = :policyName
                        )
                        UPDATE "ANALYSIS"
                           SET "VULNERABILITY_POLICY_ID" = (SELECT "ID" FROM "VULN_POLICY")
                         WHERE "ID" = :analysisId
                        """)
                .bind("policyName", vulnPolicy.name())
                .bind("analysisId", analysisId)
                .execute());

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final var policyCondition = new PolicyCondition();
        policyCondition.setPolicy(policy);
        policyCondition.setSubject(PolicyCondition.Subject.PACKAGE_URL);
        policyCondition.setOperator(PolicyCondition.Operator.IS);
        policyCondition.setValue("value");
        qm.persist(policyCondition);

        final var policyViolation = new PolicyViolation();
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setComponent(componentB);
        policyViolation.setType(PolicyViolation.Type.OPERATIONAL);
        policyViolation.setText("text");
        policyViolation.setTimestamp(new Date());
        qm.persist(policyViolation);

        final var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setPolicyViolation(policyViolation);
        violationAnalysis.setComponent(componentB);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        violationAnalysis.setSuppressed(true);
        qm.persist(violationAnalysis);

        final var violationAnalysisComment = new ViolationAnalysisComment();
        violationAnalysisComment.setViolationAnalysis(violationAnalysis);
        violationAnalysisComment.setComment("comment");
        violationAnalysisComment.setCommenter("commenter");
        violationAnalysisComment.setTimestamp(new Date());
        qm.persist(violationAnalysisComment);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "includeACL": true,
                          "includeAuditHistory": true,
                          "includeComponents": true,
                          "includeProperties": true,
                          "includePolicyViolations": true,
                          "includeServices": true,
                          "includeTags": true
                        }
                        """.formatted(project.getUuid())));

        assertThat(response.getStatus()).isEqualTo(202);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("token")).isNotNull();
        assertThat(UuidUtil.isValidUUID(json.getString("token"))).isTrue();

        final Project clonedProject = qm.getProject("acme-app", "1.1.0");
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getUuid()).isNotEqualTo(project.getUuid());
        assertThat(clonedProject.getSupplier()).isNotNull();
        assertThat(clonedProject.getSupplier().getName()).isEqualTo("projectSupplier");
        assertThat(clonedProject.getManufacturer()).isNotNull();
        assertThat(clonedProject.getManufacturer().getName()).isEqualTo("projectManufacturer");
        assertThat(clonedProject.getAccessTeams()).containsOnly(team);
        assertThatJson(clonedProject.getDirectDependencies())
                .withMatcher("notSourceComponentUuid", not(equalTo(componentA.getUuid().toString())))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "objectType": "COMPONENT",
                            "uuid": "${json-unit.matches:notSourceComponentUuid}",
                            "name": "acme-lib-a",
                            "version": "2.0.0",
                            "swidTagId":"swidTagId"
                          }
                        ]
                        """);

        final List<ProjectProperty> clonedProperties = qm.getProjectProperties(clonedProject);
        assertThat(clonedProperties).satisfiesExactly(clonedProperty -> {
            assertThat(clonedProperty.getId()).isNotEqualTo(projectProperty.getId());
            assertThat(clonedProperty.getGroupName()).isEqualTo("group");
            assertThat(clonedProperty.getPropertyName()).isEqualTo("name");
            assertThat(clonedProperty.getPropertyValue()).isEqualTo("value");
            assertThat(clonedProperty.getPropertyType()).isEqualTo(PropertyType.STRING);
            assertThat(clonedProperty.getDescription()).isEqualTo("description");
        });

        assertThat(clonedProject.getTags()).extracting(Tag::getName)
                .containsOnly("tag-a", "tag-b");

        final ProjectMetadata clonedMetadata = clonedProject.getMetadata();
        assertThat(clonedMetadata).isNotNull();
        assertThat(clonedMetadata.getAuthors())
                .satisfiesExactly(contact -> assertThat(contact.getName()).isEqualTo("metadataAuthor"));
        assertThat(clonedMetadata.getSupplier())
                .satisfies(entity -> assertThat(entity.getName()).isEqualTo("metadataSupplier"));

        assertThat(qm.getAllComponents(clonedProject)).satisfiesExactlyInAnyOrder(
                clonedComponent -> {
                    assertThat(clonedComponent.getUuid()).isNotEqualTo(componentA.getUuid());
                    assertThat(clonedComponent.getName()).isEqualTo("acme-lib-a");
                    assertThat(clonedComponent.getVersion()).isEqualTo("2.0.0");
                    assertThat(clonedComponent.getSwidTagId()).isEqualTo("swidTagId");
                    assertThat(clonedComponent.getSupplier()).isNotNull();
                    assertThat(clonedComponent.getSupplier().getName()).isEqualTo("componentSupplier");
                    assertThatJson(clonedComponent.getDirectDependencies())
                            .withMatcher("notSourceComponentUuid", not(equalTo(componentB.getUuid().toString())))
                            .isEqualTo(/* language=JSON */ """
                                    [
                                      {
                                        "objectType": "COMPONENT",
                                        "uuid": "${json-unit.matches:notSourceComponentUuid}",
                                        "name": "acme-lib-b",
                                        "version": "2.1.0"
                                      }
                                    ]
                                    """);

                    assertThat(clonedComponent.getOccurrences()).satisfiesExactly(occurrence -> {
                        assertThat(occurrence.getLocation()).isEqualTo("location");
                        assertThat(occurrence.getLine()).isEqualTo(666);
                        assertThat(occurrence.getOffset()).isEqualTo(123);
                        assertThat(occurrence.getSymbol()).isEqualTo("symbol");
                    });

                    assertThat(clonedComponent.getProperties()).satisfiesExactly(property -> {
                        assertThat(property.getGroupName()).isEqualTo("groupName");
                        assertThat(property.getPropertyName()).isEqualTo("propertyName");
                        assertThat(property.getPropertyValue()).isEqualTo("propertyValue");
                        assertThat(property.getPropertyType()).isEqualTo(PropertyType.STRING);
                    });

                    assertThat(qm.getVulnerabilities(clonedComponent, false).getList(Vulnerability.class))
                            .satisfiesExactly(v -> assertThat(v.getId()).isEqualTo(vuln.getId()));

                    assertThat(qm.getAnalysis(clonedComponent, vuln)).satisfies(clonedAnalysis -> {
                        assertThat(clonedAnalysis.getId()).isNotEqualTo(analysisId);
                        assertThat(clonedAnalysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
                        assertThat(clonedAnalysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.REQUIRES_ENVIRONMENT);
                        assertThat(clonedAnalysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
                        assertThat(clonedAnalysis.getAnalysisDetails()).isEqualTo("details");
                        assertThat(clonedAnalysis.isSuppressed()).isFalse();
                        assertThat(clonedAnalysis.getVulnerabilityPolicyId()).isNotNull();
                    });
                },
                clonedComponent -> {
                    assertThat(clonedComponent.getUuid()).isNotEqualTo(componentA.getUuid());
                    assertThat(clonedComponent.getName()).isEqualTo("acme-lib-b");
                    assertThat(clonedComponent.getVersion()).isEqualTo("2.1.0");

                    assertThat(qm.getAllPolicyViolations(clonedComponent)).satisfiesExactly(clonedViolation -> {
                        assertThat(clonedViolation.getProject().getId()).isEqualTo(clonedProject.getId());
                        assertThat(clonedViolation.getPolicyCondition().getId()).isEqualTo(policyCondition.getId());
                        assertThat(clonedViolation.getType()).isEqualTo(PolicyViolation.Type.OPERATIONAL);
                        assertThat(clonedViolation.getText()).isEqualTo("text");
                        assertThat(clonedViolation.getTimestamp()).isNotNull();

                        final ViolationAnalysis clonedViolationAnalysis = clonedViolation.getAnalysis();
                        assertThat(clonedViolationAnalysis).isNotNull();
                        assertThat(clonedViolationAnalysis.getProject().getId()).isEqualTo(clonedProject.getId());
                        assertThat(clonedViolationAnalysis.getComponent().getId()).isEqualTo(clonedComponent.getId());
                        assertThat(clonedViolationAnalysis.getAnalysisState()).isEqualTo(ViolationAnalysisState.APPROVED);
                        assertThat(clonedViolationAnalysis.isSuppressed()).isTrue();
                        assertThat(clonedViolationAnalysis.getAnalysisComments()).satisfiesExactly(clonedComment -> {
                            assertThat(clonedComment.getComment()).isEqualTo("comment");
                            assertThat(clonedComment.getCommenter()).isEqualTo("commenter");
                            assertThat(clonedComment.getTimestamp()).isNotNull();
                        });
                    });
                });

        assertThat(qm.getAllServiceComponents(clonedProject)).satisfiesExactly(clonedService -> {
            assertThat(clonedService.getUuid()).isNotEqualTo(service.getUuid());
            assertThat(clonedService.getName()).isEqualTo("acme-service");
            assertThat(clonedService.getVersion()).isEqualTo("3.0.0");
        });
    }

    @Test
    void cloneProjectConflictTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.0.0"
                        }
                        """.formatted(project.getUuid())));

        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(getPlainTextBody(response)).isEqualTo("A project with the specified name and version already exists.");
    }

    @Test
    void cloneProjectWithAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var accessProject = new Project();
        accessProject.setName("acme-app-a");
        accessProject.setVersion("1.0.0");
        accessProject.setAccessTeams(Set.of(team));
        qm.persist(accessProject);

        final var noAccessProject = new Project();
        noAccessProject.setName("acme-app-b");
        noAccessProject.setVersion("2.0.0");
        qm.persist(noAccessProject);

        Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "1.1.0"
                        }
                        """.formatted(noAccessProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "1.1.0"
                        }
                        """.formatted(accessProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
    }

    @Test
    void validateProjectVersionsActiveInactiveTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, null, false);
        qm.createProject("ABC", null, "2.0", null, null, null, new Date(), false);
        qm.createProject("ABC", null, "3.0", null, null, null, null, false);

        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getString("name"));
        Assertions.assertEquals(3, json.getJsonArray("versions").size());

        Assertions.assertNotNull(json.getJsonArray("versions").getJsonObject(0).getJsonString("uuid").getString());
        Assertions.assertEquals("1.0", json.getJsonArray("versions").getJsonObject(0).getJsonString("version").getString());
        Assertions.assertFalse(json.getJsonArray("versions").getJsonObject(0).getBoolean("isLatest"));
        Assertions.assertTrue(json.getJsonArray("versions").getJsonObject(0).getBoolean("active"));

        Assertions.assertNotNull(json.getJsonArray("versions").getJsonObject(1).getJsonString("uuid").getString());
        Assertions.assertEquals("2.0", json.getJsonArray("versions").getJsonObject(1).getJsonString("version").getString());
        Assertions.assertFalse(json.getJsonArray("versions").getJsonObject(0).getBoolean("isLatest"));
        Assertions.assertTrue(json.getJsonArray("versions").getJsonObject(0).getBoolean("active"));

        Assertions.assertNotNull(json.getJsonArray("versions").getJsonObject(2).getJsonString("uuid").getString());
        Assertions.assertEquals("3.0", json.getJsonArray("versions").getJsonObject(2).getJsonString("version").getString());
        Assertions.assertFalse(json.getJsonArray("versions").getJsonObject(0).getBoolean("isLatest"));
        Assertions.assertTrue(json.getJsonArray("versions").getJsonObject(0).getBoolean("active"));
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/4048
    void issue4048RegressionTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE, Permissions.VIEW_PORTFOLIO);
        final int projectsPerLevel = 10;
        final int maxDepth = 5;

        final Map<Integer, List<UUID>> projectUuidsByLevel = new HashMap<>();

        // Create multiple parent-child hierarchies of projects.
        for (int i = 0; i < maxDepth; i++) {
            final List<UUID> parentUuids = projectUuidsByLevel.get(i - 1);

            for (int j = 0; j < projectsPerLevel; j++) {
                final UUID parentUuid = i > 0 ? parentUuids.get(j) : null;

                final JsonObjectBuilder requestBodyBuilder = Json.createObjectBuilder()
                        .add("name", "project-%d-%d".formatted(i, j))
                        .add("version", "%d.%d".formatted(i, j));
                if (parentUuid != null) {
                    requestBodyBuilder.add("parent", Json.createObjectBuilder()
                            .add("uuid", parentUuid.toString()));
                }

                final Response response = jersey.target(V1_PROJECT)
                        .request()
                        .header(X_API_KEY, apiKey)
                        .put(Entity.json(requestBodyBuilder.build().toString()));
                assertThat(response.getStatus()).isEqualTo(201);
                final JsonObject jsonResponse = parseJsonObject(response);

                projectUuidsByLevel.compute(i, (ignored, uuids) -> {
                    final UUID uuid = UUID.fromString(jsonResponse.getString("uuid"));
                    if (uuids == null) {
                        return new ArrayList<>(List.of(uuid));
                    }

                    uuids.add(uuid);
                    return uuids;
                });
            }
        }

        // Pick out the UUIDs of projects that should have a parent (i.e. level 1 or above).
        final List<UUID> childUuids = projectUuidsByLevel.entrySet().stream()
                .filter(entry -> entry.getKey() > 0)
                .map(Map.Entry::getValue)
                .flatMap(List::stream)
                .toList();

        // Create a [uuid -> level] mapping for better assertion failure reporting.
        final Map<UUID, Integer> levelByChildUuid = projectUuidsByLevel.entrySet().stream()
                .filter(entry -> entry.getKey() > 0)
                .flatMap(entry -> {
                    final Integer level = entry.getKey();
                    return entry.getValue().stream().map(uuid -> Map.entry(uuid, level));
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // Request all child projects individually.
        // Ensure that the parent field is populated for all of them.
        for (final UUID uuid : childUuids) {
            final Response response = jersey.target(V1_PROJECT + "/" + uuid)
                    .request()
                    .header(X_API_KEY, apiKey)
                    .get();
            assertThat(response.getStatus()).isEqualTo(200);
            final JsonObject json = parseJsonObject(response);
            assertThat(json.getJsonObject("parent"))
                    .withFailMessage("Parent missing on level: " + levelByChildUuid.get(uuid))
                    .isNotEmpty();
        }
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/4413
    void cloneProjectWithBrokenDependencyGraphTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setDirectDependencies("[{\"uuid\":\"d6b6f140-f547-4fe2-a98c-f4942ad51f86\"}]");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        component.setDirectDependencies("[{\"uuid\":\"61503628-d2a2-447b-b99c-701b9d492cbd\"}]");
        qm.persist(component);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "includeComponents": true,
                          "includeServices": true
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);

        final Project clonedProject = qm.getProject("acme-app", "1.1.0");
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getDirectDependencies()).isEqualTo(
                "[{\"uuid\": \"d6b6f140-f547-4fe2-a98c-f4942ad51f86\"}]");

        assertThat(qm.getAllComponents(clonedProject).getFirst().getDirectDependencies()).isEqualTo(
                "[{\"uuid\": \"61503628-d2a2-447b-b99c-701b9d492cbd\"}]");
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3883
    void issue3883RegressionTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE, Permissions.VIEW_PORTFOLIO);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "name": "acme-app-parent",
                          "version": "1.0.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final String parentProjectUuid = parseJsonObject(response).getString("uuid");

        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "name": "acme-app",
                          "version": "1.0.0",
                          "parent": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(parentProjectUuid)));
        assertThat(response.getStatus()).isEqualTo(201);
        final String childProjectUuid = parseJsonObject(response).getString("uuid");

        response = jersey.target(V1_PROJECT + "/" + parentProjectUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "acme-app-parent",
                  "version": "1.0.0",
                  "classifier": "APPLICATION",
                  "uuid": "${json-unit.any-string}",
                  "children": [
                    {
                      "name": "acme-app",
                      "version": "1.0.0",
                      "classifier": "APPLICATION",
                      "uuid": "${json-unit.any-string}",
                      "isLatest": false,
                      "active": true
                    }
                  ],
                  "tags": [],
                  "isLatest": false,
                  "active": true,
                  "versions": [
                    {
                      "uuid": "${json-unit.any-string}",
                      "version": "1.0.0",
                      "isLatest": false,
                      "active": true
                    }
                  ]
                }
                """);

        response = jersey.target(V1_PROJECT + "/" + childProjectUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "acme-app",
                  "version": "1.0.0",
                  "classifier": "APPLICATION",
                  "uuid": "${json-unit.any-string}",
                  "parent": {
                    "name": "acme-app-parent",
                    "version": "1.0.0",
                    "uuid": "${json-unit.any-string}"
                  },
                  "children": [],
                  "tags": [],
                  "isLatest": false,
                  "active": true,
                  "versions": [
                    {
                      "uuid": "${json-unit.any-string}",
                      "version": "1.0.0",
                      "isLatest": false,
                      "active": true
                    }
                  ]
                }
                """);
    }

    @Test
    void createProjectAsLatestTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure initial value is false when not specified
        Assertions.assertFalse(json.getBoolean("isLatest"));

        project.setVersion("2.0");
        project.setIsLatest(true);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure value of latest version is true when specified
        Assertions.assertTrue(json.getBoolean("isLatest"));
        String v20uuid = json.getString("uuid");

        project.setVersion("2.1");
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure value of latest version is true when specified
        Assertions.assertTrue(json.getBoolean("isLatest"));
        // ensure v2.0 is no longer latest
        Assertions.assertFalse(qm.getProject(v20uuid).isLatest());
    }

    @Test
    void createProjectAsLatestWithACLTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var accessProject = new Project();
        accessProject.setName("acme-app-a");
        accessProject.setVersion("1.0.0");
        accessProject.setIsLatest(true);
        accessProject.setAccessTeams(Set.of(team));
        qm.persist(accessProject);

        final var noAccessProject = new Project();
        noAccessProject.setName("acme-app-b");
        noAccessProject.setVersion("2.0.0");
        noAccessProject.setIsLatest(true);
        qm.persist(noAccessProject);

        Project project = new Project();
        project.setName(accessProject.getName());
        project.setVersion("1.0.1");
        project.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertTrue(json.getBoolean("isLatest"));

        project.setName(noAccessProject.getName());
        project.setVersion("3.0.0");
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void createProjectAsInactiveTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure initial value is false when not specified
        Assertions.assertTrue(json.getBoolean("active"));

        project.setVersion("2.0");
        project.setInactiveSince(new Date());
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure value of latest version is true when specified
        Assertions.assertFalse(json.getBoolean("active"));
    }

    @Test
    void updateProjectAsLatestTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        // create project not as latest
        Project project = qm.createProject("ABC", null, "1.0", null, null, null,
                null, false, false);

        // make it latest by update
        var jsonProject = qm.detach(project);
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertTrue(json.getBoolean("isLatest"));

        // add another project version, "forget" to make it latest
        final Project newProject = qm.createProject("ABC", null, "1.0.1", null, null, null,
                null, false, false);
        // make the new version latest afterwards via update
        jsonProject = qm.detach(newProject);
        jsonProject.setIsLatest(true);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure is now latest
        Assertions.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest
        Assertions.assertFalse(qm.getProject(project.getName(), project.getVersion()).isLatest());
    }

    @Test
    void updateProjectAsLatestWithACLAndAccessTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var accessLatestProject = new Project();
        accessLatestProject.setName("acme-app-a");
        accessLatestProject.setVersion("1.0.0");
        accessLatestProject.setIsLatest(true);
        accessLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update
        final var jsonProject = qm.detach(accessNotLatestProject);
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure is now latest
        Assertions.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest (bypass db cache)
        qm.getPersistenceManager().refreshAll();
        Assertions.assertFalse(qm.getProject(accessLatestProject.getName(), accessLatestProject.getVersion()).isLatest());
    }

    @Test
    void updateProjectAsLatestWithACLAndNoAccessTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var noAccessLatestProject = new Project();
        noAccessLatestProject.setName("acme-app-a");
        noAccessLatestProject.setVersion("1.0.0");
        noAccessLatestProject.setIsLatest(true);
        qm.persist(noAccessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update (but have no access to old latest)
        final var jsonProject = qm.detach(accessNotLatestProject);
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonProject, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(403, response.getStatus(), 0);
        // ensure old is still latest
        Assertions.assertTrue(qm.getProject(noAccessLatestProject.getName(), noAccessLatestProject.getVersion()).isLatest());
    }

    @Test
    void patchProjectAsLatestTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        // create project not as latest
        Project project = qm.createProject("ABC", null, "1.0", null, null, null,
                null, false, false);

        // make it latest by patch
        var jsonProject = new Project();
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertTrue(json.getBoolean("isLatest"));

        // add another project version, "forget" to make it latest
        final Project newProject = qm.createProject("ABC", null, "1.0.1", null, null, null,
                null, false, false);
        // make the new version latest afterwards via update
        jsonProject = new Project();
        jsonProject.setIsLatest(true);
        response = jersey.target(V1_PROJECT + "/" + newProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assertions.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        // ensure is now latest
        Assertions.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest
        Assertions.assertFalse(qm.getProject(project.getName(), project.getVersion()).isLatest());
    }

    @Test
    void patchProjectAsLatestWithACLAndAccessTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var accessLatestProject = new Project();
        accessLatestProject.setName("acme-app-a");
        accessLatestProject.setVersion("1.0.0");
        accessLatestProject.setIsLatest(true);
        accessLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update
        final var jsonProject = new Project();
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT + "/" + accessNotLatestProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        // ensure is now latest
        Assertions.assertTrue(json.getBoolean("isLatest"));
        // ensure old is no longer latest (bypass db cache)
        qm.getPersistenceManager().refreshAll();
        Assertions.assertFalse(qm.getProject(accessLatestProject.getName(), accessLatestProject.getVersion()).isLatest());
    }

    @Test
    void patchProjectAsLatestWithACLAndNoAccessTest() {
        enablePortfolioAccessControl();

        final var noAccessLatestProject = new Project();
        noAccessLatestProject.setName("acme-app-a");
        noAccessLatestProject.setVersion("1.0.0");
        noAccessLatestProject.setIsLatest(true);
        qm.persist(noAccessLatestProject);

        final var accessNotLatestProject = new Project();
        accessNotLatestProject.setName("acme-app-a");
        accessNotLatestProject.setVersion("1.0.1");
        accessNotLatestProject.setIsLatest(false);
        accessNotLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessNotLatestProject);

        // make the new version latest afterwards via update (but have no access to old latest)
        final var jsonProject = new Project();
        jsonProject.setIsLatest(true);
        Response response = jersey.target(V1_PROJECT + "/" + accessNotLatestProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(jsonProject));
        Assertions.assertEquals(403, response.getStatus(), 0);
        // ensure old is still latest
        qm.getPersistenceManager().refreshAll();
        Assertions.assertTrue(qm.getProject(noAccessLatestProject.getName(), noAccessLatestProject.getVersion()).isLatest());
    }

    @Test
    void cloneProjectAsLatestTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app-a");
        project.setVersion("1.0.0");
        project.setIsLatest(true);
        qm.persist(project);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "makeCloneLatest": true
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);

        final Project clonedProject = qm.getProject("acme-app-a", "1.1.0");
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.isLatest()).isTrue();

        qm.getPersistenceManager().refresh(project);
        assertThat(project.isLatest()).isFalse();
    }

    @Test
    void getLatestProjectTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, null, false);
        qm.createProject("Acme Example", null, "1.0.2", null, null, null, null, true, false);
        qm.createProject("Different project", null, "1.0.3", null, null, null, null, true, false);

        Response response = jersey.target(V1_PROJECT_LATEST + "Acme Example")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Acme Example", json.getString("name"));
        Assertions.assertEquals("1.0.2", json.getString("version"));
    }

    @Test
    void getLatestProjectWithAclEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        // Create project and give access to current principal's team.
        Project accessProject = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false, false);
        accessProject.setAccessTeams(Set.of(team));
        qm.persist(accessProject);

        accessProject = qm.createProject("acme-app-a", null, "1.0.2", null, null, null, null, true, false);
        accessProject.setAccessTeams(Set.of(team));
        qm.persist(accessProject);

        final Response response = jersey.target(V1_PROJECT_LATEST + "acme-app-a")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("acme-app-a", json.getString("name"));
        Assertions.assertEquals("1.0.2", json.getString("version"));
    }

    @Test
    void getLatestProjectWithAclEnabledNoAccessTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        // Create projects and give NO access
        qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false, false);
        qm.createProject("acme-app-a", null, "1.0.2", null, null, null, null, true, false);

        final Response response = jersey.target(V1_PROJECT_LATEST + "acme-app-a")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void createProjectIsLatestPreviousLatestInaccessibleTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var previousLatest = new Project();
        previousLatest.setName("acme-app");
        previousLatest.setVersion("1.0.0");
        previousLatest.setIsLatest(true);
        qm.persist(previousLatest);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "version": "2.0.0",
                          "isLatest": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        qm.getPersistenceManager().refresh(previousLatest);
        assertThat(previousLatest.isLatest()).isTrue();
        assertThat(qm.getProject("acme-app", "2.0.0")).isNull();
    }

    @Test
    void createProjectAsUserWithAclEnabledAndExistingTeamByUuidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userSessionToken = new SessionTokenService().createSession(testUser.getId());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userSessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "tags": [],
                          "active": true,
                          "isLatest": false
                        }
                        """);

        assertThat(qm.getProject("acme-app", null)).satisfies(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly(team.getName()));
    }

    @Test
    void createProjectAsUserWithAclEnabledAndExistingTeamByNameTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String sessionToken = new SessionTokenService().createSession(testUser.getId());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "name": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getName())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "tags": [],
                          "isLatest":false,
                          "active": true
                        }
                        """);

        assertThat(qm.getProject("acme-app", null)).satisfies(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly(team.getName()));
    }

    @Test
    void createProjectAsUserWithAclEnabledAndWithoutTeamTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userSessionToken = new SessionTokenService().createSession(testUser.getId());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userSessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "tags": [],
                          "isLatest":false,
                          "active":true
                        }
                        """);

        assertThat(qm.getProject("acme-app", null)).satisfies(project ->
                assertThat(project.getAccessTeams()).isEmpty());
    }

    @Test
    void createProjectAsUserWithNotAllowedExistingTeamTest() {
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        testUser.setPermissions(List.of(qm.createPermission(Permissions.PORTFOLIO_MANAGEMENT_CREATE.name(), null)));

        final String userSessionToken = new SessionTokenService().createSession(testUser.getId());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userSessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The team with UUID %s can not be assigned because it does not exist, \
                or is not accessible to the authenticated principal.""", team.getUuid());
    }

    @Test
    void createProjectAsUserWithAclEnabledAndNotMemberOfTeamAdminTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT, Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userSessionToken = new SessionTokenService().createSession(testUser.getId());

        final Team otherTeam = qm.createTeam("otherTeam");

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userSessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(otherTeam.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "tags": [],
                          "isLatest":false,
                          "active":true
                        }
                        """);

        assertThat(qm.getProject("acme-app", null)).satisfies(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly("otherTeam"));
    }

    @Test
    void createProjectAsUserWithAclEnabledAndTeamNotExistingNoAdminTest() {
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        testUser.setPermissions(List.of(qm.createPermission(Permissions.PORTFOLIO_MANAGEMENT_CREATE.name(), null)));

        final String userSessionToken = new SessionTokenService().createSession(testUser.getId());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userSessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "419c32eb-5a30-47d5-8a9a-fc0cda651314"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The team with UUID 419c32eb-5a30-47d5-8a9a-fc0cda651314 \
                can not be assigned because it does not exist, or is not \
                accessible to the authenticated principal.""");
    }

    @Test
    void createProjectAsUserWithAclEnabledAndTeamNotExistingAdminTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT, Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);

        final String userSessionToken = new SessionTokenService().createSession(testUser.getId());

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header("Authorization", "Bearer " + userSessionToken)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "419c32eb-5a30-47d5-8a9a-fc0cda651314"
                            }
                          ]
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The team with UUID 419c32eb-5a30-47d5-8a9a-fc0cda651314 \
                can not be assigned because it does not exist, or is not \
                accessible to the authenticated principal.""");
    }

    @Test
    void createProjectAsApiKeyWithAclEnabledAndWithExistentTeamTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-app",
                          "accessTeams": [
                            {
                              "uuid": "%s"
                            }
                          ]
                        }
                        """.formatted(team.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "acme-app",
                          "classifier": "APPLICATION",
                          "children": [],
                          "tags": [],
                          "isLatest":false,
                          "active":true
                        }
                        """);

        assertThat(qm.getProject("acme-app", null)).satisfies(project ->
                assertThat(project.getAccessTeams()).extracting(Team::getName).containsOnly(team.getName()));
    }

    @Test
    void patchActiveProjectToInactiveTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        // create project as active
        Project project = qm.createProject("ABC", null, null, null, null, null,
                null, false, false);

        // make it inactive by patch
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(/* language=JSON */ """
                        {
                          "name": "ABC-Updated",
                          "active": false
                        }
                        """));
        Assertions.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "tags": [],
                          "inactiveSince": "${json-unit.any-number}",
                          "isLatest":false,
                          "active": false
                        }
                        """);
    }

    @Test
    void patchInactiveProjectToActiveTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        // create project as inactive
        Project project = qm.createProject("ABC", null, null, null, null, null,
                new Date(), false, false);

        // make it active by patch
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method(HttpMethod.PATCH, Entity.json(/* language=JSON */ """
                        {
                          "name": "ABC-Updated",
                          "active": true
                        }
                        """));
        Assertions.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "tags": [],
                          "isLatest":false,
                          "active": true
                        }
                        """);
    }

    @Test
    void updateActiveProjectToInactiveTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        // create project as active
        Project project = qm.createProject("ABC", null, null, null, null, null,
                null, false, false);

        // make it inactive by update
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "ABC-Updated",
                          "active": false
                        }
                        """.formatted(project.getUuid())));
        Assertions.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "classifier":"APPLICATION",
                          "tags": [],
                          "inactiveSince": "${json-unit.any-number}",
                          "isLatest":false,
                          "active": false
                        }
                        """);
    }

    @Test
    void updateInactiveProjectToActiveTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        // create project as inactive
        Project project = qm.createProject("ABC", null, null, null, null, null,
                new Date(), false, false);

        // make it active by update
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "ABC-Updated",
                          "active": true
                        }
                        """.formatted(project.getUuid())));
        Assertions.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "name": "ABC-Updated",
                          "classifier":"APPLICATION",
                          "tags": [],
                          "isLatest":false,
                          "active": true
                        }
                        """);
    }

    @Test
    void shouldReturnCollectionProjectMetricsInConciseList() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var regularProject = new Project();
        regularProject.setName("acme-regular");
        qm.persist(regularProject);

        final var collectionProject = new Project();
        collectionProject.setName("acme-collection");
        collectionProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(collectionProject, List.of(), false);

        final var childProject = new Project();
        childProject.setName("acme-child");
        childProject.setParent(collectionProject);
        qm.persist(childProject);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();

            final var regularMetrics = new ProjectMetrics();
            regularMetrics.setProjectId(regularProject.getId());
            regularMetrics.setCritical(1);
            regularMetrics.setComponents(2);
            regularMetrics.setFirstOccurrence(Date.from(dbNow));
            regularMetrics.setLastOccurrence(Date.from(dbNow));
            testDao.createProjectMetrics(regularMetrics);

            final var childMetrics = new ProjectMetrics();
            childMetrics.setProjectId(childProject.getId());
            childMetrics.setCritical(5);
            childMetrics.setHigh(3);
            childMetrics.setComponents(10);
            childMetrics.setFirstOccurrence(Date.from(dbNow));
            childMetrics.setLastOccurrence(Date.from(dbNow));
            testDao.createProjectMetrics(childMetrics);
        });

        final Response response = jersey.target(V1_PROJECT + "/concise")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(3);

        final JsonObject collectionObj = jsonArray.stream()
                .map(JsonObject.class::cast)
                .filter(o -> "acme-collection".equals(o.getString("name")))
                .findFirst().orElseThrow();
        assertThatJson(collectionObj.getJsonObject("metrics").toString())
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 5,
                          "high": 3,
                          "components": 10
                        }
                        """);

        final JsonObject regularObj = jsonArray.stream()
                .map(JsonObject.class::cast)
                .filter(o -> "acme-regular".equals(o.getString("name")))
                .findFirst().orElseThrow();
        assertThatJson(regularObj.getJsonObject("metrics").toString())
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 1,
                          "components": 2
                        }
                        """);
    }

    @Test
    void shouldSortConciseListByLastRiskScoreIncludingCollectionProjects() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setLastInheritedRiskScore(10.0);
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        projectB.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(projectB, List.of(), false);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        projectC.setParent(projectB);
        projectC.setLastInheritedRiskScore(6.0);
        qm.persist(projectC);

        final var projectD = new Project();
        projectD.setName("acme-app-d");
        projectD.setLastInheritedRiskScore(5.0);
        qm.persist(projectD);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();

            final var childMetrics = new ProjectMetrics();
            childMetrics.setProjectId(projectC.getId());
            childMetrics.setInheritedRiskScore(7.0);
            childMetrics.setFirstOccurrence(Date.from(dbNow));
            childMetrics.setLastOccurrence(Date.from(dbNow));
            testDao.createProjectMetrics(childMetrics);
        });

        final Response response = jersey
                .target(V1_PROJECT + "/concise")
                .queryParam("sortName", "lastRiskScore")
                .queryParam("sortOrder", "desc")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("4");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(4);
        assertThat(jsonArray)
                .extracting(value -> ((JsonObject) value).getString("name"))
                .containsExactly(
                        "acme-app-a",
                        "acme-app-b",
                        "acme-app-c",
                        "acme-app-d");
        assertThat(jsonArray)
                .extracting(value -> ((JsonObject) value).getJsonNumber("lastRiskScore").doubleValue())
                .containsExactly(10.0, 7.0, 6.0, 5.0);

        final JsonObject collectionObj = jsonArray.getJsonObject(1);
        assertThatJson(collectionObj.getJsonObject("metrics").toString())
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "inheritedRiskScore": 7.0
                        }
                        """);
    }

    @Test
    void shouldSortConciseListByLastRiskScoreWithoutMetricsExpansion() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.setLastInheritedRiskScore(3.0);
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        projectB.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(projectB, List.of(), false);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        projectC.setParent(projectB);
        projectC.setLastInheritedRiskScore(2.0);
        qm.persist(projectC);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();

            final var childMetrics = new ProjectMetrics();
            childMetrics.setProjectId(projectC.getId());
            childMetrics.setInheritedRiskScore(8.0);
            childMetrics.setFirstOccurrence(Date.from(dbNow));
            childMetrics.setLastOccurrence(Date.from(dbNow));
            testDao.createProjectMetrics(childMetrics);
        });

        final Response response = jersey
                .target(V1_PROJECT + "/concise")
                .queryParam("sortName", "lastRiskScore")
                .queryParam("sortOrder", "desc")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("3");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray)
                .extracting(value -> ((JsonObject) value).getString("name"))
                .containsExactly("acme-app-b", "acme-app-a", "acme-app-c");
        assertThat(jsonArray.getJsonObject(0).containsKey("metrics")).isFalse();
    }

    @Test
    void shouldReturnCollectionProjectMetricsForChildrenConciseEndpoint() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var parent = new Project();
        parent.setName("parent-collection");
        parent.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(parent, List.of(), false);

        final var nestedCollection = new Project();
        nestedCollection.setName("nested-collection");
        nestedCollection.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        nestedCollection.setParent(parent);
        qm.createProject(nestedCollection, List.of(), false);

        final var leafGrandchild = new Project();
        leafGrandchild.setName("leaf-grandchild");
        leafGrandchild.setParent(nestedCollection);
        qm.persist(leafGrandchild);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate dbToday = handle.createQuery("SELECT CURRENT_DATE").mapTo(LocalDate.class).one();
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", dbToday);
            final Instant dbNow = handle.createQuery("SELECT CURRENT_TIMESTAMP").mapTo(Instant.class).one();

            final var grandchildMetrics = new ProjectMetrics();
            grandchildMetrics.setProjectId(leafGrandchild.getId());
            grandchildMetrics.setInheritedRiskScore(4.0);
            grandchildMetrics.setCritical(2);
            grandchildMetrics.setFirstOccurrence(Date.from(dbNow));
            grandchildMetrics.setLastOccurrence(Date.from(dbNow));
            testDao.createProjectMetrics(grandchildMetrics);
        });

        final Response response = jersey.target(V1_PROJECT + "/concise/" + parent.getUuid() + "/children")
                .queryParam("includeMetrics", "true")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(1);
        final JsonObject nested = jsonArray.getJsonObject(0);
        assertThat(nested.getString("name")).isEqualTo("nested-collection");
        // The nested collection's metrics aggregate recursively from its leaf descendant.
        assertThatJson(nested.getJsonObject("metrics").toString())
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 2,
                          "inheritedRiskScore": 4.0
                        }
                        """);
    }

    @Test
    void shouldCreateCollectionProjectWithoutClassifier() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-collection",
                          "version": "1.0",
                          "classifier": "LIBRARY",
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN");
        assertThat(json.containsKey("classifier")).isFalse();
    }

    @Test
    void shouldUpdateProjectToCollectionAndNullClassifier() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "acme-app",
                          "version": "1.0",
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN"
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN");
        assertThat(json.containsKey("classifier")).isFalse();
    }

    @Test
    void shouldPatchCollectionLogicAndNullClassifier() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        final Response response = jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN");
        assertThat(json.containsKey("classifier")).isFalse();
    }

    @Test
    void shouldNotAllowClassifierOnExistingCollectionViaPatch() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = qm.createProject("acme-collection", null, "1.0", null, null, null, null, false);
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.persist(project);

        final Response response = jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "classifier": "APPLICATION"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN");
        assertThat(json.containsKey("classifier")).isFalse();
    }

    @Test
    void shouldCreateProjectWithNonExistentCollectionTag() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-collection",
                          "version": "1.0",
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
                          "collectionTag": {"name": "new-tag"}
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN_WITH_TAG");
        assertThat(json.getJsonObject("collectionTag").getString("name")).isEqualTo("new-tag");
        assertThat(qm.getTagByName("new-tag")).isNotNull();
    }

    @Test
    void shouldUpdateProjectWithNonExistentCollectionTag() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = qm.createProject("acme-collection", null, "1.0", null, null, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "acme-collection",
                          "version": "1.0",
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
                          "collectionTag": {"name": "new-tag"}
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN_WITH_TAG");
        assertThat(json.getJsonObject("collectionTag").getString("name")).isEqualTo("new-tag");
        assertThat(qm.getTagByName("new-tag")).isNotNull();
    }

    @Test
    void shouldPatchProjectWithNonExistentCollectionTag() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final var project = qm.createProject("acme-collection", null, "1.0", null, null, null, null, false);

        final Response response = jersey
                .target(V1_PROJECT + "/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "collectionLogic": "AGGREGATE_DIRECT_CHILDREN_WITH_TAG",
                          "collectionTag": {"name": "new-tag"}
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getString("collectionLogic")).isEqualTo("AGGREGATE_DIRECT_CHILDREN_WITH_TAG");
        assertThat(json.getJsonObject("collectionTag").getString("name")).isEqualTo("new-tag");
        assertThat(qm.getTagByName("new-tag")).isNotNull();
    }

    @Test
    void shouldCloneCollectionProject() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Tag prodTag = qm.createTag("prod");

        final var project = new Project();
        project.setName("acme-collection");
        project.setVersion("1.0");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        project.setCollectionTag(prodTag);
        qm.createProject(project, List.of(), false);

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "version": "2.0",
                          "includeTags": true
                        }
                        """.formatted(project.getUuid())));
        assertThat(response.getStatus()).isEqualTo(202);

        final Project clonedProject = qm.getProject("acme-collection", "2.0");
        assertThat(clonedProject).isNotNull();
        assertThat(clonedProject.getUuid()).isNotEqualTo(project.getUuid());
        assertThat(clonedProject.getCollectionLogic()).isEqualTo(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        assertThat(clonedProject.getCollectionTag()).isNotNull();
        assertThat(clonedProject.getCollectionTag().getName()).isEqualTo("prod");
    }

    @Test
    void shouldNotLeakInaccessibleParentViaGetProjectByUuidWhenAclEnabled() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var parent = qm.createProject("secret-parent", null, "1.0", null, null, null, null, false);
        final var child = qm.createProject("acme-child", null, "1.0", null, parent, null, null, false);
        child.addAccessTeam(super.team);

        final Response response = jersey.target(V1_PROJECT + "/" + child.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.parent")
                .isAbsent();
    }

    @Test
    void shouldNotLeakInaccessibleParentViaProjectLookupWhenAclEnabled() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var parent = qm.createProject("secret-parent", null, "1.0", null, null, null, null, false);
        final var child = qm.createProject("acme-child", null, "1.0", null, parent, null, null, false);
        child.addAccessTeam(super.team);

        final Response response = jersey.target(V1_PROJECT + "/lookup")
                .queryParam("name", "acme-child")
                .queryParam("version", "1.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.parent")
                .isAbsent();
    }

    @Test
    void shouldNotLeakInaccessibleParentViaUpdateProjectWhenAclEnabled() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var parent = qm.createProject("secret-parent", null, "1.0", null, null, null, null, false);
        final var child = qm.createProject("acme-child", null, "1.0", null, parent, null, null, false);
        child.addAccessTeam(super.team);

        final Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "acme-child",
                          "version": "1.0",
                          "description": "renamed"
                        }
                        """.formatted(child.getUuid())));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.parent")
                .isAbsent();
    }

    @Test
    void shouldNotLeakInaccessibleVersionsViaGetProjectByUuidWhenAclEnabled() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleVersion = qm.createProject("shared-name", null, "1.0", null, null, null, null, false);
        accessibleVersion.addAccessTeam(super.team);
        qm.persist(accessibleVersion);
        final var inaccessibleVersion = qm.createProject("shared-name", null, "2.0", null, null, null, null, false);

        final Response response = jersey.target(V1_PROJECT + "/" + accessibleVersion.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.versions[*].uuid")
                .isArray()
                .containsExactly(accessibleVersion.getUuid().toString());
    }

    @Test
    void shouldFilterProjectsBySearchTextOnNameAndTag() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        qm.bind(projectB, List.of(qm.createTag("tag-foo")));

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);
        qm.bind(projectC, List.of(qm.createTag("tag-bar")));

        Response response = jersey
                .target(V1_PROJECT)
                .queryParam("searchText", "acme-app-a")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].name")
                .isArray()
                .containsExactlyInAnyOrder("acme-app-a");

        response = jersey
                .target(V1_PROJECT)
                .queryParam("searchText", "tag-foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].name")
                .isArray()
                .containsExactlyInAnyOrder("acme-app-b");

        response = jersey
                .target(V1_PROJECT)
                .queryParam("searchText", "tag-bar")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].name")
                .isArray()
                .containsExactlyInAnyOrder("acme-app-c");
    }

    @Test
    void shouldFilterConciseProjectsBySearchTextOnNameAndTag() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        qm.bind(projectB, List.of(qm.createTag("tag-foo")));

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);
        qm.bind(projectC, List.of(qm.createTag("tag-bar")));

        Response response = jersey
                .target(V1_PROJECT + "/concise")
                .queryParam("searchText", "acme-app-a")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].name")
                .isArray()
                .containsExactlyInAnyOrder("acme-app-a");

        response = jersey
                .target(V1_PROJECT + "/concise")
                .queryParam("searchText", "tag-foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].name")
                .isArray()
                .containsExactlyInAnyOrder("acme-app-b");

        response = jersey
                .target(V1_PROJECT + "/concise")
                .queryParam("searchText", "tag-bar")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].name")
                .isArray()
                .containsExactlyInAnyOrder("acme-app-c");
    }

}
