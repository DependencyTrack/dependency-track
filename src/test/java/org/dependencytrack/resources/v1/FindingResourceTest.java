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

import alpine.Config;
import alpine.model.About;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;
import static org.apache.commons.io.IOUtils.resourceToString;
import java.nio.charset.StandardCharsets;

import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.math.BigDecimal;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v1.FindingResource.MEDIA_TYPE_SARIF_JSON;

class FindingResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(FindingResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    void getFindingsByProjectTest() {
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
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(3, json.size());
        Assertions.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assertions.assertEquals("Component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(1).getString("matrix"));
        Assertions.assertEquals("Component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(2).getString("matrix"));
    }

    @Test
    void getFindingsByProjectEmptyTest() {
        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("com.acme");
        metaComponent.setName("acme-lib");
        metaComponent.setLatestVersion("1.2.3");
        metaComponent.setLastCheck(new Date());
        qm.persist(metaComponent);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_FINDING + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void getFindingsByProjectInvalidTest() {
        Response response = jersey.target(V1_FINDING + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void exportFindingsByProjectTest() {
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
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(Config.getInstance().getApplicationName(), json.getJsonObject("meta").getString("application"));
        Assertions.assertEquals(Config.getInstance().getApplicationVersion(), json.getJsonObject("meta").getString("version"));
        Assertions.assertNotNull(json.getJsonObject("meta").getString("timestamp"));
        Assertions.assertEquals("Acme Example", json.getJsonObject("project").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject("project").getString("version"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject("project").getString("uuid"));
        Assertions.assertEquals("1.2", json.getString("version")); // FPF version
        JsonArray findings = json.getJsonArray("findings");
        Assertions.assertEquals(3, findings.size());
        Assertions.assertEquals("Component A", findings.getJsonObject(0).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", findings.getJsonObject(0).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-1", findings.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.CRITICAL.name(), findings.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), findings.getJsonObject(0).getString("matrix"));
        Assertions.assertEquals("Component A", findings.getJsonObject(1).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", findings.getJsonObject(1).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-2", findings.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.HIGH.name(), findings.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(findings.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), findings.getJsonObject(1).getString("matrix"));
        Assertions.assertEquals("Component B", findings.getJsonObject(2).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", findings.getJsonObject(2).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-3", findings.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.MEDIUM.name(), findings.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), findings.getJsonObject(2).getString("matrix"));
    }

    @Test
    void exportFindingsByProjectInvalidTest() {
        Response response = jersey.target(V1_FINDING + "/project/" + UUID.randomUUID().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void getFindingsByProjectWithComponentLatestVersionTest() {
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
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(3, json.size());
        Assertions.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assertions.assertEquals("2.0.0", json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
        Assertions.assertEquals("Component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(1).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), json.getJsonObject(1).getString("matrix"));
        Assertions.assertEquals("2.0.0", json.getJsonObject(1).getJsonObject("component").getString("latestVersion"));
        Assertions.assertEquals("Component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(2).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), json.getJsonObject(2).getString("matrix"));
        Assertions.assertEquals("3.0.0", json.getJsonObject(2).getJsonObject("component").getString("latestVersion"));
    }

    @Test
    void getFindingsByProjectWithComponentLatestVersionWithoutRepositoryMetaComponent() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assertions.assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assertions.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        Assertions.assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assertions.assertThrows(NullPointerException.class, () -> json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
    }

    @Test
    void getAllFindings() {
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
        Response response = jersey.target(V1_FINDING)
                .queryParam("sortName", "component.projectName")
                .queryParam("sortOrder", "asc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(5, json.size());
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1_child.getName() ,json.getJsonObject(3).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1_child.getVersion() ,json.getJsonObject(3).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1_child.getUuid().toString(), json.getJsonObject(3).getJsonObject("component").getString("project"));
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(4).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p2.getName() ,json.getJsonObject(4).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p2.getVersion() ,json.getJsonObject(4).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p2.getUuid().toString(), json.getJsonObject(4).getJsonObject("component").getString("project"));
    }

    @Test
    void getAllFindingsWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p1_child = qm.createProject("Acme Example", null, "1.0", null, p1, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Team team = qm.createTeam("Team Acme");
        ApiKey apiKey = qm.createApiKey(team);
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
        Response response = jersey.target(V1_FINDING).request()
                .header(X_API_KEY, apiKey.getKey())
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(3, json.size());
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        Assertions.assertEquals(date.getTime() ,json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        Assertions.assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        Assertions.assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
    }

    @Test
    void getAllFindingsGroupedByVulnerability() {
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
        Response response = jersey.target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(4, json.size());
        Assertions.assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assertions.assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(3, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assertions.assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assertions.assertEquals("INTERNAL", json.getJsonObject(3).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-4", json.getJsonObject(3).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.LOW.name(), json.getJsonObject(3).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(3).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(1, json.getJsonObject(3).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    void getAllFindingsGroupedByVulnerabilityWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p1_child = qm.createProject("Acme Example", null, "1.0", null, p1, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Team team = qm.createTeam("Team Acme");
        ApiKey apiKey = qm.createApiKey(team);
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
        Response response = jersey.target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey.getKey())
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(3, json.size());
        Assertions.assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assertions.assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(1, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        Assertions.assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        Assertions.assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        Assertions.assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        Assertions.assertEquals("NONE", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        Assertions.assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        Assertions.assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        Assertions.assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assertions.assertEquals(1, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    void getAllFindingsWithEpssFilterTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        
        // Create vulnerabilities with different EPSS scores
        Vulnerability v1 = createVulnerabilityWithEpss("Vuln-1", Severity.CRITICAL, new BigDecimal("0.1"));
        Vulnerability v2 = createVulnerabilityWithEpss("Vuln-2", Severity.HIGH, new BigDecimal("0.5"));
        Vulnerability v3 = createVulnerabilityWithEpss("Vuln-3", Severity.MEDIUM, new BigDecimal("0.9"));
        
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c3, AnalyzerIdentity.NONE);
        
        // Test filtering by epssFrom
        Response response = jersey.target(V1_FINDING)
                .queryParam("epssFrom", "0.3")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(2, json.size());
        
        // Test filtering by epssTo
        response = jersey.target(V1_FINDING)
                .queryParam("epssTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        
        // Test filtering by epssFrom and epssTo range
        response = jersey.target(V1_FINDING)
                .queryParam("epssFrom", "0.3")
                .queryParam("epssTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @Test
    void getAllFindingsGroupedByVulnerabilityWithEpssFilterTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        
        // Create vulnerabilities with different EPSS scores
        Vulnerability v1 = createVulnerabilityWithEpss("Vuln-1", Severity.CRITICAL, new BigDecimal("0.2"));
        Vulnerability v2 = createVulnerabilityWithEpss("Vuln-2", Severity.HIGH, new BigDecimal("0.6"));
        Vulnerability v3 = createVulnerabilityWithEpss("Vuln-3", Severity.MEDIUM, new BigDecimal("0.8"));
        
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c3, AnalyzerIdentity.NONE);
        
        // Test filtering grouped findings by EPSS range
        Response response = jersey.target(V1_FINDING + "/grouped")
                .queryParam("epssFrom", "0.5")
                .queryParam("epssTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @Test
    void getAllFindingsWithEpssPercentileFilterTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        
        // Create vulnerabilities with different EPSS percentiles
        Vulnerability v1 = createVulnerabilityWithEpssPercentile("Vuln-1", Severity.CRITICAL, new BigDecimal("0.1"));
        Vulnerability v2 = createVulnerabilityWithEpssPercentile("Vuln-2", Severity.HIGH, new BigDecimal("0.5"));
        Vulnerability v3 = createVulnerabilityWithEpssPercentile("Vuln-3", Severity.MEDIUM, new BigDecimal("0.9"));
        
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c3, AnalyzerIdentity.NONE);
        
        // Test filtering by epssPercentileFrom
        Response response = jersey.target(V1_FINDING)
                .queryParam("epssPercentileFrom", "0.3")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(2, json.size());
        
        // Test filtering by epssPercentileTo
        response = jersey.target(V1_FINDING)
                .queryParam("epssPercentileTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        
        // Test filtering by epssPercentileFrom and epssPercentileTo range
        response = jersey.target(V1_FINDING)
                .queryParam("epssPercentileFrom", "0.3")
                .queryParam("epssPercentileTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @Test
    void getAllFindingsGroupedByVulnerabilityWithEpssPercentileFilterTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        
        // Create vulnerabilities with different EPSS percentiles
        Vulnerability v1 = createVulnerabilityWithEpssPercentile("Vuln-1", Severity.CRITICAL, new BigDecimal("0.2"));
        Vulnerability v2 = createVulnerabilityWithEpssPercentile("Vuln-2", Severity.HIGH, new BigDecimal("0.6"));
        Vulnerability v3 = createVulnerabilityWithEpssPercentile("Vuln-3", Severity.MEDIUM, new BigDecimal("0.8"));
        
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c3, AnalyzerIdentity.NONE);
        
        // Test filtering grouped findings by EPSS percentile range
        Response response = jersey.target(V1_FINDING + "/grouped")
                .queryParam("epssPercentileFrom", "0.5")
                .queryParam("epssPercentileTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @ParameterizedTest
    @MethodSource("getSARIFFindingsByProjectTestParameters")
    void getSARIFFindingsByProjectTest(String query, String expectedResponsePath) throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(project, "Component 1", "1.1.4");
        Component c2 = createComponent(project, "Component 2", "2.78.123");
        c1.setGroup("org.acme");
        c2.setGroup("com.xyz");
        c1.setPurl("pkg:maven/org.acme/component1@1.1.4?type=jar");
        c2.setPurl("pkg:maven/com.xyz/component2@2.78.123?type=jar");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL, "Vuln Title 1", "This is a description", null, 80, Source.INTERNAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH, "Vuln Title 2", "   Yet another description but with surrounding whitespaces   ", "", 46, Source.INTERNAL);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.LOW, "Vuln Title 3", "A description-with-hyphens-(and parentheses)", "  Recommendation with whitespaces  ", 23, Source.INTERNAL);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.MEDIUM, "Vuln Title 4", "This is a vulnerability that has GITHUB Advisory as a source", null, 20, Source.GITHUB);

        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c2, AnalyzerIdentity.NONE);

        var target = jersey.target(V1_FINDING + "/project/" + project.getUuid().toString());
        if (query != null) {
            target = target.queryParam("source", query);
        }
        Response response = target.request()
            .header(HttpHeaders.ACCEPT, MEDIA_TYPE_SARIF_JSON)
            .header(X_API_KEY, apiKey)
            .get(Response.class);

        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(MEDIA_TYPE_SARIF_JSON, response.getHeaderString(HttpHeaders.CONTENT_TYPE));
        final String jsonResponse = getPlainTextBody(response);
        final String version = new About().getVersion();
        final String fullName = "OWASP Dependency-Track - " + version;
        String expectedTemplate = resourceToString(expectedResponsePath, StandardCharsets.UTF_8);
        String expected = expectedTemplate
            .replace("{{VERSION}}", version)
            .replace("{{FULL_NAME}}", fullName);
        assertThatJson(jsonResponse).isEqualTo(expected);
    }

    private static Stream<Arguments> getSARIFFindingsByProjectTestParameters() {
        return Stream.of(
            Arguments.of("INTERNAL", "/unit/sarif/expected-internal.sarif.json"),
            Arguments.of(null, "/unit/sarif/expected-all.sarif.json")
        );
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

    private Vulnerability createVulnerability(String vulnId, Severity severity, String title, String description, String recommendation, Integer cweId, Vulnerability.Source source) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(source);
        vulnerability.setSeverity(severity);
        vulnerability.setTitle(title);
        vulnerability.setDescription(description);
        vulnerability.setRecommendation(recommendation);
        vulnerability.setCwes(List.of(cweId));
        return qm.createVulnerability(vulnerability, false);
    }

    private Vulnerability createVulnerabilityWithEpss(String vulnId, Severity severity, BigDecimal epssScore) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        vulnerability.setEpssScore(epssScore);
        return qm.createVulnerability(vulnerability, false);
    }

    private Vulnerability createVulnerabilityWithEpssPercentile(String vulnId, Severity severity, BigDecimal epssPercentile) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        vulnerability.setEpssPercentile(epssPercentile);
        return qm.createVulnerability(vulnerability, false);
    }
}
