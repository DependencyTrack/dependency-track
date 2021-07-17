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

import alpine.Config;
import alpine.filters.ApiFilter;
import alpine.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
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
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("Component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(1).getString("matrix"));
        Assert.assertEquals("Component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
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
        Assert.assertEquals("1.0", json.getString("version")); // FPF version
        JsonArray findings = json.getJsonArray("findings");
        Assert.assertEquals(3, findings.size());
        Assert.assertEquals("Component A", findings.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-1", findings.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.CRITICAL.name(), findings.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assert.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), findings.getJsonObject(0).getString("matrix"));
        Assert.assertEquals("Component A", findings.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-2", findings.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.HIGH.name(), findings.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assert.assertFalse(findings.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assert.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), findings.getJsonObject(1).getString("matrix"));
        Assert.assertEquals("Component B", findings.getJsonObject(2).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", findings.getJsonObject(2).getJsonObject("component").getString("version"));
        Assert.assertEquals("Vuln-3", findings.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assert.assertEquals(Severity.MEDIUM.name(), findings.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
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
        return qm.createVulnerability(vulnerability, false);
    }
}
