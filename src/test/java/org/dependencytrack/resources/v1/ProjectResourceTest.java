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
import alpine.event.framework.EventService;
import alpine.model.IConfigProperty.PropertyType;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.cyclonedx.model.ExternalReference.Type;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.event.CloneProjectEvent;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.CloneProjectTask;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.hamcrest.CoreMatchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;

public class ProjectResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ProjectResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @After
    @Override
    public void after() throws Exception {
        EventService.getInstance().unsubscribe(CloneProjectTask.class);
        super.after();
    }

    @Test
    public void getProjectsDefaultRequestTest() {
        for (int i=0; i<1000; i++) {
            qm.createProject("Acme Example", null, String.valueOf(i), null, null, null, true, false);
        }
        Response response = jersey.target(V1_PROJECT)
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

        final Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT+"/lookup")
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        final var parentProject = new Project();
        parentProject.setName("parent");
        parentProject.setVersion("1.2.3");
        qm.persist(parentProject);

        final var manufacturer = new OrganizationalEntity();
        manufacturer.setName("manufacturer");

        final var supplier = new OrganizationalEntity();
        supplier.setName("supplier");

        final var property = new ProjectProperty();
        property.setGroupName("groupName");
        property.setPropertyName("propertyName");
        property.setPropertyValue("propertyValue");
        property.setPropertyType(PropertyType.STRING);

        final var externalRef = new ExternalReference();
        externalRef.setUrl("https://example.com");
        externalRef.setType(Type.WEBSITE);

        final var project = new Project();
        project.setAuthor("author");
        project.setPublisher("publisher");
        project.setManufacturer(manufacturer);
        project.setSupplier(supplier);
        project.setGroup("group");
        project.setName("name");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.LIBRARY);
        project.setDescription("description");
        project.setDirectDependencies("[{\"uuid\":\"c162be63-35f0-4059-b28b-327e6a01390a\"}]");
        project.setCpe("cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other");
        project.setPurl("pkg:maven/namespace/name@1.0.0");
        project.setSwidTagId("swidTagId");
        project.setParent(parentProject);
        project.setProperties(List.of(property));
        project.setLastBomImport(new Date(1643767322000L));
        project.setLastBomImportFormat("lastBomImportFormat");
        project.setLastInheritedRiskScore(66.6);
        project.setActive(false);
        project.setExternalReferences(List.of(externalRef));
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("tag-1")));

        final var metadataAuthor = new OrganizationalContact();
        metadataAuthor.setName("metadataAuthor");
        final var metadataSupplier = new OrganizationalEntity();
        metadataSupplier.setName("metadataSupplier");
        final var metadata = new ProjectMetadata();
        metadata.setAuthors(List.of(metadataAuthor));
        metadata.setSupplier(metadataSupplier);
        metadata.setProject(project);
        qm.persist(metadata);

        final var metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setCritical(6);
        metrics.setHigh(6);
        metrics.setMedium(6);
        metrics.setLow(6);
        metrics.setUnassigned(6);
        metrics.setVulnerabilities(6);
        metrics.setVulnerableComponents(6);
        metrics.setComponents(6);
        metrics.setFindingsTotal(6);
        metrics.setFindingsAudited(6);
        metrics.setFindingsUnaudited(6);
        metrics.setInheritedRiskScore(66.6);
        metrics.setSuppressed(6);
        metrics.setPolicyViolationsTotal(6);
        metrics.setPolicyViolationsFail(6);
        metrics.setPolicyViolationsInfo(6);
        metrics.setPolicyViolationsWarn(6);
        metrics.setPolicyViolationsAudited(6);
        metrics.setPolicyViolationsUnaudited(6);
        metrics.setPolicyViolationsLicenseAudited(6);
        metrics.setPolicyViolationsLicenseTotal(6);
        metrics.setPolicyViolationsLicenseUnaudited(6);
        metrics.setPolicyViolationsOperationalAudited(6);
        metrics.setPolicyViolationsOperationalTotal(6);
        metrics.setPolicyViolationsOperationalUnaudited(6);
        metrics.setPolicyViolationsSecurityAudited(6);
        metrics.setPolicyViolationsSecurityTotal(6);
        metrics.setPolicyViolationsSecurityUnaudited(6);
        metrics.setFirstOccurrence(new Date(1677812583000L));
        metrics.setLastOccurrence(new Date(1677812583000L));
        qm.persist(metrics);

        final UUID parentProjectUuid = parentProject.getUuid();
        final UUID projectUuid = project.getUuid();

        // Nuke L1 and L2 cache and close PM to ensure all changes are flushed.
        qm.getPersistenceManager().getPersistenceManagerFactory().getDataStoreCache().evictAll();
        qm.getPersistenceManager().evictAll();
        qm.close();

        final Response response = jersey.target(V1_PROJECT + "/" + projectUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("parentProjectUuid", equalTo(parentProjectUuid.toString()))
                .withMatcher("projectUuid", equalTo(projectUuid.toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "active": false,
                          "author": "author",
                          "children": [],
                          "classifier": "LIBRARY",
                          "cpe": "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other",
                          "description": "description",
                          "directDependencies": "[{\\"uuid\\":\\"c162be63-35f0-4059-b28b-327e6a01390a\\"}]",
                          "externalReferences": [
                            {
                              "type": "website",
                              "url": "https://example.com"
                            }
                          ],
                          "group": "group",
                          "lastBomImport": 1643767322000,
                          "lastBomImportFormat": "lastBomImportFormat",
                          "lastInheritedRiskScore": 66.6,
                          "manufacturer": {
                            "name": "manufacturer"
                          },
                          "metadata": {
                            "supplier": {
                              "name": "metadataSupplier"
                            },
                            "authors": [
                              {
                                "name":"metadataAuthor"
                              }
                            ]
                          },
                          "metrics":{
                            "critical": 6,
                            "high": 6,
                            "medium": 6,
                            "low": 6,
                            "unassigned": 6,
                            "vulnerabilities": 6,
                            "vulnerableComponents":6,
                            "components": 6,
                            "suppressed": 6,
                            "findingsTotal": 6,
                            "findingsAudited": 6,
                            "findingsUnaudited": 6,
                            "inheritedRiskScore": 66.6,
                            "policyViolationsFail": 6,
                            "policyViolationsWarn": 6,
                            "policyViolationsInfo": 6,
                            "policyViolationsTotal": 6,
                            "policyViolationsAudited": 6,
                            "policyViolationsUnaudited": 6,
                            "policyViolationsSecurityTotal": 6,
                            "policyViolationsSecurityAudited": 6,
                            "policyViolationsSecurityUnaudited": 6,
                            "policyViolationsLicenseTotal": 6,
                            "policyViolationsLicenseAudited": 6,
                            "policyViolationsLicenseUnaudited": 6,
                            "policyViolationsOperationalTotal": 6,
                            "policyViolationsOperationalAudited": 6,
                            "policyViolationsOperationalUnaudited": 6,
                            "firstOccurrence": 1677812583000,
                            "lastOccurrence": 1677812583000
                          },
                          "name": "name",
                          "parent": {
                            "name": "parent",
                            "uuid": "${json-unit.matches:parentProjectUuid}",
                            "version": "1.2.3"
                          },
                          "properties": [
                            {
                              "groupName": "groupName",
                              "propertyName": "propertyName",
                              "propertyType": "STRING",
                              "propertyValue": "propertyValue"
                            }
                          ],
                          "publisher": "publisher",
                          "purl": "pkg:maven/namespace/name@1.0.0",
                          "supplier": {
                            "name": "supplier"
                          },
                          "swidTagId": "swidTagId",
                          "tags": [
                            {
                              "name": "tag-1"
                            }
                          ],
                          "uuid": "${json-unit.matches:projectUuid}",
                          "version": "1.0.0",
                          "versions": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "version": "1.0.0"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void getProjectByInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID())
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
        Response response = jersey.target(V1_PROJECT + "/tag/" + "production")
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
        Response response = jersey.target(V1_PROJECT + "/tag/" + "production")
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
        Response response = jersey.target(V1_PROJECT + "/tag/" + "stable")
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A project with the specified name already exists.", body);
    }

    @Test
    public void createProjectWithoutVersionDuplicateTest() {
        Project project = new Project();
        project.setName("Acme Example");
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(project, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateProjectTest() {
        Project project = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        project.setDescription("Test project");
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        var response = jersey.target(V1_PROJECT)
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
        response = jersey.target(V1_PROJECT)
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
        response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteProjectInvalidUuidTest() {
        qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString())
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
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
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
        final var response = jersey.target(V1_PROJECT + "/" + p1.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true)
                .method("PATCH", Entity.json(jsonProject));
        Assert.assertEquals(Response.Status.CONFLICT.getStatusCode(), response.getStatus());
        Assert.assertEquals(p1, qm.getObjectByUuid(Project.class, p1.getUuid()));
    }

    @Test
    public void patchProjectNotFoundTest() {
        final var response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID())
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
        jsonProject.setActive(false);
        jsonProject.setName("new name");
        jsonProject.setPublisher("new publisher");
        jsonProject.setTags(Stream.of("tag4").map(name -> {
            var t = new Tag();
            t.setName(name);
            return t;
        }).collect(Collectors.toUnmodifiableList()));
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
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
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
                          "properties": [],
                          "tags": [
                            {
                              "name": "tag4"
                            }
                          ],
                          "active": false
                        }
                        """);
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

        final var response = jersey.target(V1_PROJECT + "/" + project.getUuid())
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
                          "properties": [],
                          "tags": [],
                          "active": true
                        }
                        """);

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
    public void getRootProjectsTest() {
        Project parent = qm.createProject("ABC", null, "1.0", null, null, null, true, false);
        Project child = qm.createProject("DEF", null, "1.0", null, parent, null, true, false);
        qm.createProject("GHI", null, "1.0", null, child, null, true, false);
        Response response = jersey.target(V1_PROJECT)
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
        Response response = jersey.target(V1_PROJECT + "/" + parent.getUuid().toString() + "/children")
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

        Response response = jersey.target(V1_PROJECT + "/withoutDescendantsOf/" + parent.getUuid())
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
    public void cloneProjectTest() {
        EventService.getInstance().subscribe(CloneProjectEvent.class, CloneProjectTask.class);

        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("projectManufacturer");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("projectSupplier");

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setManufacturer(projectManufacturer);
        project.setSupplier(projectSupplier);
        project.setAccessTeams(List.of(team));
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

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        component.setSupplier(componentSupplier);
        qm.persist(component);

        final var service = new ServiceComponent();
        service.setProject(project);
        service.setName("acme-service");
        service.setVersion("3.0.0");
        qm.persist(service);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        final Analysis analysis = qm.makeAnalysis(component, vuln, AnalysisState.NOT_AFFECTED,
                AnalysisJustification.REQUIRES_ENVIRONMENT, AnalysisResponse.WILL_NOT_FIX, "details", false);
        qm.makeAnalysisComment(analysis, "comment", "commenter");

        final Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0",
                          "includeACL": true,
                          "includeAuditHistory": true,
                          "includeComponents": true,
                          "includeProperties": true,
                          "includeServices": true,
                          "includeTags": true
                        }
                        """.formatted(project.getUuid())));

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));

        await("Cloning completion")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(50))
                .untilAsserted(() -> {
                    final Project clonedProject = qm.getProject("acme-app", "1.1.0");
                    assertThat(clonedProject).isNotNull();
                    assertThat(clonedProject.getUuid()).isNotEqualTo(project.getUuid());
                    assertThat(clonedProject.getSupplier()).isNotNull();
                    assertThat(clonedProject.getSupplier().getName()).isEqualTo("projectSupplier");
                    assertThat(clonedProject.getManufacturer()).isNotNull();
                    assertThat(clonedProject.getManufacturer().getName()).isEqualTo("projectManufacturer");
                    assertThat(clonedProject.getAccessTeams()).containsOnly(team);

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

                    assertThat(qm.getAllComponents(clonedProject)).satisfiesExactly(clonedComponent -> {
                        assertThat(clonedComponent.getUuid()).isNotEqualTo(component.getUuid());
                        assertThat(clonedComponent.getName()).isEqualTo("acme-lib");
                        assertThat(clonedComponent.getVersion()).isEqualTo("2.0.0");
                        assertThat(clonedComponent.getSupplier()).isNotNull();
                        assertThat(clonedComponent.getSupplier().getName()).isEqualTo("componentSupplier");

                        assertThat(qm.getAllVulnerabilities(clonedComponent)).containsOnly(vuln);

                        assertThat(qm.getAnalysis(clonedComponent, vuln)).satisfies(clonedAnalysis -> {
                            assertThat(clonedAnalysis.getId()).isNotEqualTo(analysis.getId());
                            assertThat(clonedAnalysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
                            assertThat(clonedAnalysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.REQUIRES_ENVIRONMENT);
                            assertThat(clonedAnalysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
                            assertThat(clonedAnalysis.getAnalysisDetails()).isEqualTo("details");
                            assertThat(clonedAnalysis.isSuppressed()).isFalse();
                        });
                    });

                    assertThat(qm.getAllServiceComponents(clonedProject)).satisfiesExactly(clonedService -> {
                        assertThat(clonedService.getUuid()).isNotEqualTo(service.getUuid());
                        assertThat(clonedService.getName()).isEqualTo("acme-service");
                        assertThat(clonedService.getVersion()).isEqualTo("3.0.0");
                    });
                });
    }

    @Test
    public void cloneProjectConflictTest() {
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
    public void cloneProjectWithAclTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        final var accessProject = new Project();
        accessProject.setName("acme-app-a");
        accessProject.setVersion("1.0.0");
        accessProject.setAccessTeams(List.of(team));
        qm.persist(accessProject);

        final var noAccessProject = new Project();
        noAccessProject.setName("acme-app-b");
        noAccessProject.setVersion("2.0.0");
        qm.persist(noAccessProject);

        Response response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0"
                        }
                        """.formatted(noAccessProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(getPlainTextBody(response)).isEqualTo("Access to the specified project is forbidden");

        response = jersey.target("%s/clone".formatted(V1_PROJECT)).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json("""
                        {
                          "project": "%s",
                          "version": "1.1.0"
                        }
                        """.formatted(accessProject.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/4048
    public void issue4048RegressionTest() {
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

}
