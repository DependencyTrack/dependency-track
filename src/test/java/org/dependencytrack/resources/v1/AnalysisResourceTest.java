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

import alpine.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class AnalysisResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(AnalysisResource.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void retrieveAnalysisTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        qm.makeAnalysis(project, component, vulnerability, AnalysisState.NOT_AFFECTED, true);
        Response response = target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(AnalysisState.NOT_AFFECTED.name(), json.getString("analysisState"));
        Assert.assertTrue(json.getBoolean("isSuppressed"));
    }

    @Test
    public void retrieveAnalysisInvalidProjectUuidTest() {
        qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        Response response = target(V1_ANALYSIS)
                .queryParam("project", UUID.randomUUID())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void retrieveAnalysisInvalidComponentUuidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        Response response = target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", UUID.randomUUID())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void retrieveAnalysisInvalidVulnerabilityUuidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        Response response = target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The vulnerability could not be found.", body);
    }

    @Test
    public void updateGlobalAnalysisTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        qm.makeAnalysis(null, component, vulnerability, AnalysisState.NOT_AFFECTED, true);
        AnalysisRequest request = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, "Not an issue", true);
        Response response = target(V1_ANALYSIS + "/global")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(AnalysisState.NOT_AFFECTED.name(), json.getString("analysisState"));
        Assert.assertTrue(json.getBoolean("isSuppressed"));
        Analysis globalAnalysis = qm.getAnalysis(null, component, vulnerability);
        Assert.assertNull(globalAnalysis.getProject());
        Assert.assertEquals(component.getUuid(), globalAnalysis.getComponent().getUuid());
        Assert.assertEquals(vulnerability.getUuid(), globalAnalysis.getVulnerability().getUuid());
    }

    @Test
    public void updateAnalysisTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        qm.makeAnalysis(project, component, vulnerability, AnalysisState.NOT_AFFECTED, true);
        AnalysisRequest request = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, "Not an issue", true);
        Response response = target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(AnalysisState.NOT_AFFECTED.name(), json.getString("analysisState"));
        Assert.assertTrue(json.getBoolean("isSuppressed"));
        Analysis analysis = qm.getAnalysis(project, component, vulnerability);
        Assert.assertEquals(project.getUuid(), analysis.getProject().getUuid());
        Assert.assertEquals(component.getUuid(), analysis.getComponent().getUuid());
        Assert.assertEquals(vulnerability.getUuid(), analysis.getVulnerability().getUuid());
    }

    @Test
    public void updateAnalysisChangeStateTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        List<Component> components = new ArrayList<>();
        components.add(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);
        qm.makeAnalysis(project, component, vulnerability, AnalysisState.IN_TRIAGE, false);
        AnalysisRequest request = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, "Not an issue", true);
        Response response = target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(AnalysisState.NOT_AFFECTED.name(), json.getString("analysisState"));
        Assert.assertTrue(json.getBoolean("isSuppressed"));
        Assert.assertEquals(2, json.getJsonArray("analysisComments").size());
        Assert.assertNotNull(json.getJsonArray("analysisComments").getJsonObject(0).getJsonNumber("timestamp"));
        Assert.assertEquals("IN_TRIAGE → NOT_AFFECTED", json.getJsonArray("analysisComments").getJsonObject(0).getString("comment"));
        Assert.assertNotNull(json.getJsonArray("analysisComments").getJsonObject(1).getJsonNumber("timestamp"));
        Assert.assertEquals("Not an issue", json.getJsonArray("analysisComments").getJsonObject(1).getString("comment"));
        Analysis analysis = qm.getAnalysis(project, component, vulnerability);
        Assert.assertEquals(project.getUuid(), analysis.getProject().getUuid());
        Assert.assertEquals(component.getUuid(), analysis.getComponent().getUuid());
        Assert.assertEquals(vulnerability.getUuid(), analysis.getVulnerability().getUuid());
    }
}
