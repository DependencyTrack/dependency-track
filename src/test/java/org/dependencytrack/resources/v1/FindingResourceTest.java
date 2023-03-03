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

import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.Response;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.CweImporter;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import alpine.Config;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;

public class FindingResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(FindingResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        new CweImporter().processCweDefinitions();
    }

    @Test
    public void getFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "component A", "1.0");
        Component c2 = createComponent(p1, "component B", "1.0");
        Component c3 = createComponent(p1, "component C", "1.0");
        Component c4 = createComponent(p2, "component D", "1.0");
        Component c5 = createComponent(p2, "component E", "1.0");
        Component c6 = createComponent(p2, "component F", "1.0");
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
        Assert.assertEquals("component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(1).getString("matrix"));

        Assert.assertEquals("component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(2).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(2).getString("matrix"));
    }

    @Test
    public void getFindingsByProjectInvalidTest() {
        Response response = target(V1_FINDING + "/project/" + UUID.randomUUID().toString() + "/vulnerabilities").request()
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
        Component c1 = createComponent(p1, "component A", "1.0");
        Component c2 = createComponent(p1, "component B", "1.0");
        Component c3 = createComponent(p1, "component C", "1.0");
        Component c4 = createComponent(p2, "component D", "1.0");
        Component c5 = createComponent(p2, "component E", "1.0");
        Component c6 = createComponent(p2, "component F", "1.0");
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
        Assert.assertEquals("component A", findings.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", findings.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), findings.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), findings.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("component A", findings.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", findings.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), findings.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(findings.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), findings.getJsonObject(1).getString("matrix"));
        Assert.assertEquals("component B", findings.getJsonObject(2).getJsonObject("component").getString("name"));
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

        // outdated component with known vulnerability
        Component c1 = createComponent(p1, "component-a", "1.0");
        c1.setGroup("org.acme");
        c1.setPurl("pkg:maven/org.acme/component-a@1.0");
        qm.persist(c1);
        RepositoryMetaComponent r1 = new RepositoryMetaComponent();
        Date d1 = new Date();
        r1.setLastCheck(d1);
        r1.setNamespace("org.acme");
        r1.setName("component-a");
        r1.setLatestVersion("2.0.0");
        final var now = new Date();
        r1.setPublished(now);
        r1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r1);
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);

        // outdated component with no known vulnerabilitys
        Component c2 = createComponent(p1, "component-b", "1.0");
        c2.setGroup("org.acme");
        c2.setPurl("pkg:maven/org.acme/component-b@1.0");
        qm.persist(c2);
        RepositoryMetaComponent r2 = new RepositoryMetaComponent();
        Date d2 = new Date();
        r2.setLastCheck(d2);
        r2.setNamespace("org.acme");
        r2.setName("component-b");
        r2.setLatestVersion("3.0.0");
        r2.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r2);

        // recent component
        Component c3 = createComponent(p1, "component-c", "1.0");
        c3.setGroup("org.acme");
        c3.setPurl("pkg:maven/org.acme/component-c@1.0");
        qm.persist(c3);

        // recent component with known vulnerability
        Component c4 = createComponent(p1, "component-d", "1.0");
        c4.setGroup("org.acme");
        c4.setPurl("pkg:maven/org.acme/component-d@1.0");
        qm.persist(c4);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        qm.addVulnerability(v3, c4, AnalyzerIdentity.NONE); // recent

        p1.setDirectDependencies("[{\"uuid\":\"" + c1.getUuid() + "\"}, {\"uuid\":\"" + c2.getUuid() + "\"}, {\"uuid\":\"" + c3.getUuid() + "\"}, {\"uuid\":\"" + c4.getUuid() + "\"}]");
        qm.persist(p1);

        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(4, json.size());

        Assert.assertEquals("component-a", json.getJsonObject(0).getJsonObject("component").getString("name"));
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

        Assert.assertEquals("component-a", json.getJsonObject(1).getJsonObject("component").getString("name"));
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

        Assert.assertEquals("component-d", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(2).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c4.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(2).getString("matrix"));
        Assert.assertThrows(NullPointerException.class, () -> json.getJsonObject(2).getJsonObject("component").getString("latestVersion"));

        Assert.assertEquals("component-b", json.getJsonObject(3).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(3).getJsonObject("component").getString("version"));
        Assert.assertEquals(Severity.UNASSIGNED.name(), json.getJsonObject(3).getJsonObject("vulnerability").getString("severity"));
        Assert.assertFalse(json.getJsonObject(3).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":", json.getJsonObject(3).getString("matrix"));
        Assert.assertEquals("3.0.0", json.getJsonObject(3).getJsonObject("component").getString("latestVersion"));
    }

    @Test
    public void getFindingsByProjectWithComponentWithoutRepositoryMetaComponent() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "component A", "1.0");
        c1.setPurl("pkg:maven/org.acme/component-a@1.0");

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
        Assert.assertEquals("component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
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
    public void getOutdatedComponentFindingsByProject() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

        // outdated direct dependency with vulnerability
        Component component1 = new Component();
        component1.setProject(project);
        component1.setName("component1");
        component1.setGroup("org.acme");
        component1.setVersion("1.0.0");
        component1.setPurl("pkg:maven/org.acme/component1@1.0.0");
        component1 = qm.createComponent(component1, false);
        RepositoryMetaComponent meta1 = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta1.setLastCheck(lastCheck);
        meta1.setNamespace("org.acme");
        meta1.setName("component1");
        meta1.setLatestVersion("2.0.0");
        final var now = new Date();
        meta1.setPublished(now);
        meta1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1);
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, component1, AnalyzerIdentity.NONE);

        // recent direct dependency without vulnerability
        Component component2 = new Component();
        component2.setProject(project);
        component2.setName("component2");
        component2.setGroup("org.acme");
        component2.setVersion("2.0.0");
        component2.setPurl("pkg:maven/org.acme/component2@2.0.0");
        component2 = qm.createComponent(component2, false);
        RepositoryMetaComponent meta2 = new RepositoryMetaComponent();
        meta2.setLastCheck(lastCheck);
        meta2.setNamespace("org.acme");
        meta2.setName("component2");
        meta2.setLatestVersion("2.0.0");
        meta2.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta2);

        // outdated transitive dependency without vulnerability
        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setName("component1_1");
        component1_1.setGroup("org.acme");
        component1_1.setVersion("2.0.0");
        component1_1.setPurl("pkg:maven/org.acme/component1_1@2.0.0");
        component1_1 = qm.createComponent(component1_1, false);
        RepositoryMetaComponent meta1_1 = new RepositoryMetaComponent();
        meta1_1.setLastCheck(lastCheck);
        meta1_1.setNamespace("org.acme");
        meta1_1.setName("component1_1");
        meta1_1.setLatestVersion("3.0.0");
        meta1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1);

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}, {\"uuid\":\"" + component2.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        qm.persist(project, component1);

        // should return only outdated components without findings
        Response response = target(V1_FINDING + "/project/" + project.getUuid().toString() + "/outdated").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());

        Assert.assertEquals("component1", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("2.0.0", json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
        Assert.assertEquals(now.getTime(), json.getJsonObject(0).getJsonObject("component").getJsonNumber("published").longValue());
        Assert.assertEquals(lastCheck.getTime(), json.getJsonObject(0).getJsonObject("component").getJsonNumber("lastCheck").longValue());
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
    }

    @Test
    public void getVulnerabilityComponentFindingsByProject() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

        // outdated direct dependency with vulnerability
        Component component1 = new Component();
        component1.setProject(project);
        component1.setGroup("org.acme");
        component1.setName("component1");
        component1.setVersion("1.0.0");
        component1.setPurl("pkg:maven/org.acme/component1@1.0.0");
        RepositoryMetaComponent meta1 = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta1.setLastCheck(lastCheck);
        meta1.setNamespace("org.acme");
        meta1.setName("component1");
        meta1.setLatestVersion("2.0.0");
        final var now = new Date();
        meta1.setPublished(now);
        meta1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1);
        component1 = qm.createComponent(component1, false);
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, component1, AnalyzerIdentity.NONE);

        // recent direct dependency without vulnerability
        Component component2 = new Component();
        component2.setProject(project);
        component2.setGroup("org.acme");
        component2.setName("component2");
        component2.setVersion("2.0.0");
        component2.setPurl("pkg:maven/org.acme/component2@2.0.0");
        RepositoryMetaComponent meta2 = new RepositoryMetaComponent();
        meta2.setLastCheck(lastCheck);
        meta2.setNamespace("org.acme");
        meta2.setName("component2");
        meta2.setLatestVersion("2.0.0");
        meta2.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta2);
        component2 = qm.createComponent(component2, false);

        // outdated transitive dependency without vulnerability
        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setGroup("org.acme");
        component1_1.setName("component1_1");
        component1_1.setVersion("2.0.0");
        component1_1.setPurl("pkg:maven/org.acme/component1_1@2.0.0");
        RepositoryMetaComponent meta1_1 = new RepositoryMetaComponent();
        meta1_1.setLastCheck(lastCheck);
        meta1_1.setNamespace("org.acme");
        meta1_1.setName("component1_1");
        meta1_1.setLatestVersion("3.0.0");
        meta1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1);
        component1_1 = qm.createComponent(component1_1, false);
        Vulnerability v1_1 = createVulnerability("Vuln-1_1", Severity.CRITICAL);
        qm.addVulnerability(v1_1, component1_1, AnalyzerIdentity.NONE);

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}, {\"uuid\":\"" + component2.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        qm.persist(project, component1);

        // should return only outdated components without findings
        Response response = target(V1_FINDING + "/project/" + project.getUuid().toString() + "/vulnerabilities").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(2, json.size());

        Assert.assertEquals("component1", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("2.0.0", json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
        Assert.assertEquals(now.getTime(), json.getJsonObject(0).getJsonObject("component").getJsonNumber("published").longValue());
        Assert.assertEquals(lastCheck.getTime(), json.getJsonObject(0).getJsonObject("component").getJsonNumber("lastCheck").longValue());
        Assert.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));

        Assert.assertEquals("component1_1", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("2.0.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1_1", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(project.getUuid().toString() + ":" + component1_1.getUuid().toString() + ":" + v1_1.getUuid().toString(), json.getJsonObject(1).getString("matrix"));
    }

    @Test
    public void getFindingsByProject() {
        Project p1 = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // outdated
        Component component1 = new Component();
        component1.setProject(p1);
        component1.setGroup("org.acme");
        component1.setName("component1");
        component1.setVersion("1.0.0");
        component1.setPurl("pkg:maven/org.acme/component1@1.0.0");
        RepositoryMetaComponent meta1 = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta1.setLastCheck(lastCheck);
        meta1.setNamespace("org.acme");
        meta1.setName("component1");
        meta1.setLatestVersion("2.0.0");
        meta1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1);
        component1 = qm.createComponent(component1, false);

        // not outdated, no vulnerabilities
        Component component2 = new Component();
        component2.setProject(p1);
        component2.setGroup("org.acme");
        component2.setName("component2");
        component2.setVersion("2.0.0");
        component2.setPurl("pkg:maven/org.acme/component2@2.0.0");
        RepositoryMetaComponent meta2 = new RepositoryMetaComponent();
        meta2.setLastCheck(lastCheck);
        meta2.setNamespace("org.acme");
        meta2.setName("component2");
        meta2.setLatestVersion("2.0.0");
        meta2.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta2);
        component2 = qm.createComponent(component2, false);

        // outdated, with vulnerability
        Component component1_1 = new Component();
        component1_1.setProject(p1);
        component1_1.setGroup("org.acme");
        component1_1.setName("component1_1");
        component1_1.setVersion("2.0.0");
        component1_1.setPurl("pkg:maven/org.acme/component1_1@2.0.0");
        RepositoryMetaComponent meta1_1 = new RepositoryMetaComponent();
        meta1_1.setLastCheck(lastCheck);
        meta1_1.setNamespace("org.acme");
        meta1_1.setName("component1_1");
        meta1_1.setLatestVersion("3.0.0");
        meta1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1);
        component1_1 = qm.createComponent(component1_1, false);
        Vulnerability vulnerability1_1 = createVulnerability("Vuln-1_1", Severity.HIGH);
        qm.addVulnerability(vulnerability1_1, component1_1, AnalyzerIdentity.NONE);

        p1.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}, {\"uuid\":\"" + component2.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");

        // vulnerabilities, not outdated
        Component c1 = createComponent(p1, "component A", "1.0");
        Component c2 = createComponent(p1, "component B", "1.0");
        Component c3 = createComponent(p1, "component C", "1.0");
        Component c4 = createComponent(p2, "component D", "1.0");
        Component c5 = createComponent(p2, "component E", "1.0");
        Component c6 = createComponent(p2, "component F", "1.0");
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
        Assert.assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(5, json.size());

        Assert.assertEquals("component1_1", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("2.0.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1_1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + component1_1.getUuid().toString() + ":" + vulnerability1_1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));

        Assert.assertEquals("component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(1).getString("matrix"));

        Assert.assertEquals("component A", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(2).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(2).getString("matrix"));

        Assert.assertEquals("component B", json.getJsonObject(3).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(3).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(3).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(3).getJsonObject("vulnerability").getString("severity"));
        Assert.assertEquals(80, json.getJsonObject(3).getJsonObject("vulnerability").getInt("cweId"));
        Assert.assertEquals(2, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assert.assertEquals(80, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assert.assertEquals(666, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(3).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(3).getString("matrix"));

        Assert.assertEquals("component1", json.getJsonObject(4).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0.0", json.getJsonObject(4).getJsonObject("component").getString("version"));
        Assert.assertEquals("2.0.0", json.getJsonObject(4).getJsonObject("component").getString("latestVersion"));
        Assert.assertEquals(lastCheck.getTime(), json.getJsonObject(4).getJsonObject("component").getJsonNumber("lastCheck").longValue());
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
}
