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

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.json;
import static org.dependencytrack.resources.v1.FindingResource.MEDIA_TYPE_SARIF_JSON;
import static org.hamcrest.CoreMatchers.equalTo;

import alpine.Config;
import alpine.model.About;
import alpine.model.ConfigProperty;
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import javax.ws.rs.core.HttpHeaders;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class FindingResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(FindingResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("Component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(1).getString("matrix"));
        Assert.assertEquals("Component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(2).getString("matrix"));
    }

    @Test
    public void getFindingsByProjectInvalidTest() {
        Response response = target(V1_FINDING + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void exportFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(Config.getInstance().getApplicationName(), json.getJsonObject("meta").getString("application"));
        Assert.assertEquals(Config.getInstance().getApplicationVersion(), json.getJsonObject("meta").getString("version"));
        Assert.assertNotNull(json.getJsonObject("meta").getString("timestamp"));
        Assert.assertEquals("Acme Example", json.getJsonObject("project").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject("project").getString("version"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject("project").getString("uuid"));
        Assert.assertEquals("1.2", json.getString("version")); // FPF version
        JsonArray findings = json.getJsonArray("findings");
        Assert.assertEquals(3, findings.size());
        Assert.assertEquals("Component A", findings.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", findings.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), findings.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), findings.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("Component A", findings.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", findings.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), findings.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(findings.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), findings.getJsonObject(1).getString("matrix"));
        Assert.assertEquals("Component B", findings.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", findings.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), findings.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), findings.getJsonObject(2).getString("matrix"));
    }

    @Test
    public void exportFindingsByProjectInvalidTest() {
        Response response = target(V1_FINDING + "/project/" + UUID.randomUUID().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");
        RepositoryMetaComponent r1 = new RepositoryMetaComponent();
        Date d1 = new Date();
        r1.setLastCheck(d1);
        r1.setNamespace("org.acme");
        r1.setName("component-a");
        r1.setLatestVersion("2.0.0");
        r1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r1);

        Component c2 = createComponent(p1, "Component B", "1.0");
        c2.setPurl("pkg:/maven/org.acme/component-b@1.0.0");
        RepositoryMetaComponent r2 = new RepositoryMetaComponent();
        Date d2 = new Date();
        r2.setLastCheck(d2);
        r2.setNamespace("org.acme");
        r2.setName("component-b");
        r2.setLatestVersion("3.0.0");
        r2.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r2);

        Component c3 = createComponent(p1, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");

        Component c5 = createComponent(p2, "Component E", "1.0");
        c5.setPurl("pkg:/maven/org.acme/component-e@1.0.0");
        RepositoryMetaComponent r3 = new RepositoryMetaComponent();
        Date d3 = new Date();
        r3.setLastCheck(d3);
        r3.setNamespace("org.acme");
        r3.setName("component-e");
        r3.setLatestVersion("4.0.0");
        r3.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r3);

        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("2.0.0", json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
        Assert.assertEquals("Component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(1).getString("matrix"));
        Assert.assertEquals("2.0.0", json.getJsonObject(1).getJsonObject("component").getString("latestVersion"));
        Assert.assertEquals("Component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(2).getString("matrix"));
        Assert.assertEquals("3.0.0", json.getJsonObject(2).getJsonObject("component").getString("latestVersion"));
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionWithoutRepositoryMetaComponent() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());
        Assert.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assert.assertThrows(NullPointerException.class, () -> json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
    }

    @Test
    public void getAllFindings() {
        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, true, false);
        Project p1_child = qm.createProject("Acme Example 2", null, "1.0", null, p1, null, true, false);
        Project p2 = qm.createProject("Acme Example 3", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING)
                .queryParam("sortName", "component.projectName")
                .queryParam("sortOrder", "asc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(5, json.size());
        Assert.assertEquals(date.getTime() ,json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        Assert.assertEquals(date.getTime() ,json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        Assert.assertEquals(date.getTime() ,json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
        Assert.assertEquals(date.getTime() ,json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1_child.getName() ,json.getJsonObject(3).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1_child.getVersion() ,json.getJsonObject(3).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1_child.getUuid().toString(), json.getJsonObject(3).getJsonObject("component").getString("project"));
        Assert.assertEquals(date.getTime() ,json.getJsonObject(4).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p2.getName() ,json.getJsonObject(4).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p2.getVersion() ,json.getJsonObject(4).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p2.getUuid().toString(), json.getJsonObject(4).getJsonObject("component").getString("project"));
    }

    @Test
    public void getAllFindingsWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p1_child = qm.createProject("Acme Example", null, "1.0", null, p1, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Team team = qm.createTeam("Team Acme", true);
        p1.addAccessTeam(team);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }
        Response response = target(V1_FINDING).request()
                .header(X_API_KEY, team.getApiKeys().get(0).getKey())
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals(date.getTime() ,json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        Assert.assertEquals(date.getTime() ,json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        Assert.assertEquals(date.getTime() ,json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        Assert.assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        Assert.assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
    }

    @Test
    public void getAllFindingsGroupedByVulnerability() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p1_child = qm.createProject("Acme Example", null, "1.0", null, p1, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c4, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c6, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(4, json.size());
        Assert.assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assert.assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(3, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assert.assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assert.assertEquals("INTERNAL", json.getJsonObject(3).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-4", json.getJsonObject(3).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.LOW.name(), json.getJsonObject(3).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(3).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(1, json.getJsonObject(3).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    public void getAllFindingsGroupedByVulnerabilityWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p1_child = qm.createProject("Acme Example", null, "1.0", null, p1, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Team team = qm.createTeam("Team Acme", true);
        p1.addAccessTeam(team);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c4, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c6, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }
        Response response = target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, team.getApiKeys().get(0).getKey())
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assert.assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(1, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assert.assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals("NONE", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        Assert.assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertEquals(1, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    public void getSARIFFindingsByProjectTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(project, "Component 1", "1.1.4");
        Component c2 = createComponent(project, "Component 2", "2.78.123");
        c1.setGroup("org.acme");
        c2.setGroup("com.xyz");
        c1.setPurl("pkg:maven/org.acme/component1@1.1.4?type=jar");
        c2.setPurl("pkg:maven/com.xyz/component2@2.78.123?type=jar");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL, "Vuln Title 1", "This is a description", null, 80);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH, "Vuln Title 2", "   Yet another description but with surrounding whitespaces   ", "", 46);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.LOW, "Vuln Title 3", "A description-with-hyphens-(and parentheses)", "  Recommendation with whitespaces  ", 23);

        // Note: Same vulnerability added to multiple components to test whether "rules" field doesn't contain duplicates
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);

        Response response = target(V1_FINDING + "/project/" + project.getUuid().toString()).request()
            .header(HttpHeaders.ACCEPT, MEDIA_TYPE_SARIF_JSON)
            .header(X_API_KEY, apiKey)
            .get(Response.class);

        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(MEDIA_TYPE_SARIF_JSON, response.getHeaderString(HttpHeaders.CONTENT_TYPE));
        final String jsonResponse = getPlainTextBody(response);

        assertThatJson(jsonResponse)
            .withMatcher("version", equalTo(new About().getVersion()))
            .withMatcher("fullName", equalTo("OWASP Dependency-Track - " + new About().getVersion()))
            .withMatcher("vuln1Id", equalTo(v1.getVulnId()))
            .withMatcher("vuln2Id", equalTo(v2.getVulnId()))
            .withMatcher("vuln3Id", equalTo(v3.getVulnId()))
            .withMatcher("vuln1CweId", equalTo(v1.getCwes().get(0).toString()))
            .withMatcher("vuln2CweId", equalTo(v2.getCwes().get(0).toString()))
            .withMatcher("vuln3CweId", equalTo(v3.getCwes().get(0).toString()))
            .withMatcher("vuln1Desc", equalTo(v1.getDescription().trim()))
            .withMatcher("vuln2Desc", equalTo(v2.getDescription().trim()))
            .withMatcher("vuln3Desc", equalTo(v3.getDescription().trim()))
            .withMatcher("vuln1Level", equalTo(getSARIFLevelFromSeverity(v1.getSeverity())))
            .withMatcher("vuln2Level", equalTo(getSARIFLevelFromSeverity(v2.getSeverity())))
            .withMatcher("vuln3Level", equalTo(getSARIFLevelFromSeverity(v3.getSeverity())))
            .withMatcher("vuln3Recommendation", equalTo(v3.getRecommendation().trim()))
            .withMatcher("comp1Purl", equalTo(c1.getPurl().toString()))
            .withMatcher("comp2Purl", equalTo(c2.getPurl().toString()))
            .withMatcher("comp1Name", equalTo(c1.getName()))
            .withMatcher("comp2Name", equalTo(c2.getName()))
            .withMatcher("comp1Group", equalTo(c1.getGroup()))
            .withMatcher("comp2Group", equalTo(c2.getGroup()))
            .withMatcher("comp1Version", equalTo(c1.getVersion()))
            .withMatcher("comp2Version", equalTo(c2.getVersion()))
            .isEqualTo(json("""
                {
                        "version": "2.1.0",
                        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
                        "runs": [
                          {
                            "tool": {
                              "driver": {
                                "name": "OWASP Dependency-Track",
                                "fullName": "${json-unit.matches:fullName}",
                                "version": "${json-unit.matches:version}",
                                "informationUri": "https://dependencytrack.org/",
                                "rules": [
                                  {
                                    "id": "${json-unit.matches:vuln1Id}",
                                    "name": "ImproperNeutralizationOfScript-relatedHtmlTagsInAWebPage(basicXss)",
                                    "shortDescription": {
                                      "text": "${json-unit.matches:vuln1Id}"
                                    },
                                    "fullDescription": {
                                      "text": "${json-unit.matches:vuln1Desc}"
                                    }
                                  },
                                  {
                                    "id": "${json-unit.matches:vuln2Id}",
                                    "name": "PathEquivalence:'filename'(trailingSpace)",
                                    "shortDescription": {
                                      "text": "${json-unit.matches:vuln2Id}"
                                    },
                                    "fullDescription": {
                                      "text": "${json-unit.matches:vuln2Desc}"
                                    }
                                  },
                                  {
                                    "id": "${json-unit.matches:vuln3Id}",
                                    "name": "RelativePathTraversal",
                                    "shortDescription": {
                                      "text": "${json-unit.matches:vuln3Id}"
                                    },
                                    "fullDescription": {
                                      "text": "${json-unit.matches:vuln3Desc}"
                                    }
                                  }
                                ]
                              }
                            },
                            "results": [
                              {
                                "ruleId": "${json-unit.matches:vuln1Id}",
                                "message": {
                                  "text": "${json-unit.matches:vuln1Desc}"
                                },
                                "locations": [
                                  {
                                    "logicalLocations": [
                                      {
                                        "fullyQualifiedName": "${json-unit.matches:comp1Purl}"
                                      }
                                    ]
                                  }
                                ],
                                "level": "${json-unit.matches:vuln1Level}",
                                "properties": {
                                  "name": "${json-unit.matches:comp1Name}",
                                  "group": "org.acme",
                                  "version": "${json-unit.matches:comp1Version}",
                                  "source": "INTERNAL",
                                  "cweId": "${json-unit.matches:vuln1CweId}",
                                  "cvssV3BaseScore": "",
                                  "epssScore": "",
                                  "epssPercentile": "",
                                  "severityRank": "0",
                                  "recommendation": ""
                                }
                              },
                              {
                                "ruleId": "${json-unit.matches:vuln2Id}",
                                "message": {
                                  "text": "${json-unit.matches:vuln2Desc}"
                                },
                                "locations": [
                                  {
                                    "logicalLocations": [
                                      {
                                        "fullyQualifiedName": "${json-unit.matches:comp1Purl}"
                                      }
                                    ]
                                  }
                                ],
                                "level": "${json-unit.matches:vuln2Level}",
                                "properties": {
                                  "name": "${json-unit.matches:comp1Name}",
                                  "group": "${json-unit.matches:comp1Group}",
                                  "version": "${json-unit.matches:comp1Version}",
                                  "source": "INTERNAL",
                                  "cweId": "${json-unit.matches:vuln2CweId}",
                                  "cvssV3BaseScore": "",
                                  "epssScore": "",
                                  "epssPercentile": "",
                                  "severityRank": "1",
                                  "recommendation": ""
                                }
                              },
                              {
                                "ruleId": "${json-unit.matches:vuln3Id}",
                                "message": {
                                  "text": "${json-unit.matches:vuln3Desc}"
                                },
                                "locations": [
                                  {
                                    "logicalLocations": [
                                      {
                                        "fullyQualifiedName": "${json-unit.matches:comp1Purl}"
                                      }
                                    ]
                                  }
                                ],
                                "level": "${json-unit.matches:vuln3Level}",
                                "properties": {
                                  "name": "${json-unit.matches:comp1Name}",
                                  "group": "${json-unit.matches:comp1Group}",
                                  "version": "${json-unit.matches:comp1Version}",
                                  "source": "INTERNAL",
                                  "cweId": "${json-unit.matches:vuln3CweId}",
                                  "cvssV3BaseScore": "",
                                  "epssScore": "",
                                  "epssPercentile": "",
                                  "severityRank": "3",
                                  "recommendation": "${json-unit.matches:vuln3Recommendation}"
                                }
                              },
                              {
                                "ruleId": "${json-unit.matches:vuln3Id}",
                                "message": {
                                  "text": "${json-unit.matches:vuln3Desc}"
                                },
                                "locations": [
                                  {
                                    "logicalLocations": [
                                      {
                                        "fullyQualifiedName": "${json-unit.matches:comp2Purl}"
                                      }
                                    ]
                                  }
                                ],
                                "level": "${json-unit.matches:vuln3Level}",
                                "properties": {
                                  "name": "${json-unit.matches:comp2Name}",
                                  "group": "${json-unit.matches:comp2Group}",
                                  "version": "${json-unit.matches:comp2Version}",
                                  "source": "INTERNAL",
                                  "cweId": "${json-unit.matches:vuln3CweId}",
                                  "cvssV3BaseScore": "",
                                  "epssScore": "",
                                  "epssPercentile": "",
                                  "severityRank": "3",
                                  "recommendation": "${json-unit.matches:vuln3Recommendation}"
                                }
                              }
                            ]
                          }
                        ]
                      }
            """));
    }

    private Component createComponent(Project project, String name, String version) {
        Component component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        return qm.createComponent(component, false);
    }

    private Vulnerability createVulnerability(String vulnId, Severity severity) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        return qm.createVulnerability(vulnerability, false);
    }

    private Vulnerability createVulnerability(String vulnId, Severity severity, String title, String description, String recommendation, Integer cweId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setTitle(title);
        vulnerability.setDescription(description);
        vulnerability.setRecommendation(recommendation);
        vulnerability.setCwes(List.of(cweId));
        return qm.createVulnerability(vulnerability, false);
    }

    private static String getSARIFLevelFromSeverity(Severity severity) {
        if (Severity.LOW == severity || Severity.INFO == severity) {
            return "note";
        }
        if (Severity.MEDIUM == severity) {
            return "warning";
        }
        if (Severity.HIGH == severity || Severity.CRITICAL == severity) {
            return "error";
        }
        return "none";
    }
}
