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

import alpine.common.util.UuidUtil;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpStatus;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;

public class ComponentResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(ComponentResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getComponentsDefaultRequestTest() {
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(405, response.getStatus()); // No longer prohibited in DT 4.0+
    }

    /**
     * Generate a project with different dependencies
     * @return A project with 1000 dpendencies: <ul>
     * <li>200 outdated dependencies, 75 direct and 125 transitive</li>
     * <li>800 recent dependencies, 25 direct, 775 transitive</li>
     * @throws MalformedPackageURLException
     */
    private Project prepareProject() throws MalformedPackageURLException {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        final List<String> directDepencencies = new ArrayList<>();
        // Generate 1000 dependencies
        for (int i = 0; i < 1000; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setGroup("component-group");
            component.setName("component-name-"+i);
            component.setVersion(String.valueOf(i)+".0");
            component.setPurl(new PackageURL(RepositoryType.MAVEN.toString(), "component-group", "component-name-"+i , String.valueOf(i)+".0", null, null));
            component = qm.createComponent(component, false);
            // direct depencencies
            if (i < 100) {
                // 100 direct depencencies, 900 transitive depencencies
                directDepencencies.add("{\"uuid\":\"" + component.getUuid() + "\"}");
            }
            // Recent & Outdated
            if ((i >= 25) && (i < 225)) {
                // 100 outdated components, 75 of these are direct dependencies, 25 transitive
                final var metaComponent = new RepositoryMetaComponent();
                metaComponent.setRepositoryType(RepositoryType.MAVEN);
                metaComponent.setNamespace("component-group");
                metaComponent.setName("component-name-"+i);
                metaComponent.setLatestVersion(String.valueOf(i+1)+".0");
                metaComponent.setLastCheck(new Date());
                qm.persist(metaComponent);
            } else if (i<500) {
                // 300 recent components, 25 of these are direct dependencies
                final var metaComponent = new RepositoryMetaComponent();
                metaComponent.setRepositoryType(RepositoryType.MAVEN);
                metaComponent.setNamespace("component-group");
                metaComponent.setName("component-name-"+i);
                metaComponent.setLatestVersion(String.valueOf(i)+".0");
                metaComponent.setLastCheck(new Date());
                qm.persist(metaComponent);
            } else {
                // 500 components with no RepositoryMetaComponent containing version
                // metadata, all transitive dependencies
            }
        }
        project.setDirectDependencies("[" + String.join(",", directDepencencies.toArray(new String[0])) + "]");
        return project;
    }

    @Test
    public void getOutdatedComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
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
    public void getOutdatedDirectComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
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
    public void getAllComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1000"); // 1000 dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100); // Default page size is 100
    }

    @Test
    public void getAllDirectComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
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
    public void getComponentByUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getComponentByInvalidUuidTest() {
        Response response = target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void getComponentByUuidWithRepositoryMetaDataTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("abc");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + component.getUuid())
                .queryParam("includeRepositoryMetaData", true)
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals("MAVEN", json.getJsonObject("repositoryMeta").getString("repositoryType"));
        Assert.assertEquals("org.acme", json.getJsonObject("repositoryMeta").getString("namespace"));
        Assert.assertEquals("abc", json.getJsonObject("repositoryMeta").getString("name"));
        Assert.assertEquals("2.0.0", json.getJsonObject("repositoryMeta").getString("latestVersion"));
        Assert.assertEquals(lastCheck.getTime(), json.getJsonObject("repositoryMeta").getJsonNumber("lastCheck").longValue());
    }

    @Test
    public void getComponentByIdentityWithCoordinatesTest() {
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, true, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, true, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = target(V1_COMPONENT + "/identity")
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
    public void getComponentByIdentityWithPurlTest() {
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, true, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, true, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = target(V1_COMPONENT + "/identity")
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
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, true, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, true, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = target(V1_COMPONENT + "/identity")
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
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, true, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("group");
        componentA.setName("name");
        componentA.setVersion("version");
        componentA.setPurl("pkg:maven/group/name@version?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, true, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("group");
        componentB.setName("name");
        componentB.setVersion("version");
        componentB.setPurl("pkg:maven/group/name@version?foo=bar");
        componentB = qm.createComponent(componentB, false);

        final Response response = target(V1_COMPONENT + "/identity")
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
        final Response response = target(V1_COMPONENT + "/identity")
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
    public void getComponentByHashTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/hash/" + component.getSha1())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "1");
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getComponentByInvalidHashTest() {
        Response response = target(V1_COMPONENT + "/hash/c5a8829aa3da800216b933e265dd0b97eb6f9341")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "0");
    }

    @Test
    public void createComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        Response response = target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void createComponentUpperCaseHashTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component.setSha1("640ab2bae07bedc4c163f679a746f7ab7fb5d1fa".toUpperCase());
        component.setSha256("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25".toUpperCase());
        component.setSha3_256("c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0".toUpperCase());
        component.setSha384("7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3".toUpperCase());
        component.setSha3_384("da73bfcba560692a019f52c37de4d5e3ab49ca39c6a75594e3c39d805388c4de9d0ff3927eb9e197536f5b0b3a515f0a".toUpperCase());
        component.setSha512("c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31".toUpperCase());
        component.setSha3_512("301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7".toUpperCase());
        component.setMd5("0cbc6611f5540bd0809a388dc95a615b".toUpperCase());
        Response response = target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals(component.getSha1(), json.getString("sha1"));
        Assert.assertEquals(component.getSha256(), json.getString("sha256"));
        Assert.assertEquals(component.getSha3_256(), json.getString("sha3_256"));
        Assert.assertEquals(component.getSha384(), json.getString("sha384"));
        Assert.assertEquals(component.getSha3_384(), json.getString("sha3_384"));
        Assert.assertEquals(component.getSha512(), json.getString("sha512"));
        Assert.assertEquals(component.getSha3_512(), json.getString("sha3_512"));
        Assert.assertEquals(component.getMd5(), json.getString("md5"));
    }

    @Test
    public void updateComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        component.setDescription("Test component");
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test component", json.getString("description"));
    }

    @Test
    public void updateComponentEmptyNameTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        component.setName(" ");
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + component.getUuid().toString())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentInvalidUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void internalComponentIdentificationTest() {
        Response response = target(V1_COMPONENT + "/internal/identify")
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

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

        Response response = target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component1_1_1.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(200, response.getStatus(), 0);

        Assert.assertTrue(json.get(component1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertTrue(json.get(component1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component1_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component2.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component2_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component2_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Component finalComponent2_1_1_1 = component2_1_1_1;
        Assert.assertThrows(NullPointerException.class, () -> json.get(finalComponent2_1_1_1.getUuid().toString()).asJsonObject().asJsonObject());
    }

    @Test
    public void getDependencyGraphForComponentTestWithRepositoryMetaData() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

        Component component1 = new Component();
        component1.setProject(project);
        component1.setName("Component1");
        component1.setVersion("1.0.0");
        component1.setPurl("pkg:maven/org.acme/component1");
        RepositoryMetaComponent meta1 = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta1.setLastCheck(lastCheck);
        meta1.setNamespace("org.acme");
        meta1.setName("component1");
        meta1.setLatestVersion("2.0.0");
        meta1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1);
        component1 = qm.createComponent(component1, false);

        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setName("Component1_1");
        component1_1.setVersion("2.0.0");
        component1_1.setPurl("pkg:maven/org.acme/component1_1");
        RepositoryMetaComponent meta1_1 = new RepositoryMetaComponent();
        meta1_1.setLastCheck(lastCheck);
        meta1_1.setNamespace("org.acme");
        meta1_1.setName("component1_1");
        meta1_1.setLatestVersion("3.0.0");
        meta1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1);
        component1_1 = qm.createComponent(component1_1, false);

        Component component1_1_1 = new Component();
        component1_1_1.setProject(project);
        component1_1_1.setName("Component1_1_1");
        component1_1_1.setVersion("3.0.0");
        component1_1_1.setPurl("pkg:maven/org.acme/component1_1_1");
        RepositoryMetaComponent meta1_1_1 = new RepositoryMetaComponent();
        meta1_1_1.setLastCheck(lastCheck);
        meta1_1_1.setNamespace("org.acme");
        meta1_1_1.setName("component1_1_1");
        meta1_1_1.setLatestVersion("4.0.0");
        meta1_1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1_1);
        component1_1_1 = qm.createComponent(component1_1_1, false);

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        component1_1.setDirectDependencies("[{\"uuid\":\"" + component1_1_1.getUuid() + "\"}]");

        Response response = target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component1_1_1.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(200, response.getStatus(), 0);

        Assert.assertTrue(json.get(component1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertEquals("2.0.0", json.get(component1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
        Assert.assertTrue(json.get(component1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertEquals("3.0.0", json.get(component1_1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
        Assert.assertFalse(json.get(component1_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertEquals("4.0.0", json.get(component1_1_1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
    }

    @Test
    public void getDependencyGraphForComponentInvalidProjectUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/project/" + UUID.randomUUID() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentInvalidComponentUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Response response = target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentNoDependencyGraphTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(0, json.size());
    }

    @Test
    public void getDependencyGraphForComponentIsNotComponentOfProject() {
        Project projectWithComponent = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(projectWithComponent);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        projectWithComponent.setDirectDependencies("[{\"uuid\":\"" + component.getUuid() + "\"}]");
        Project projectWithoutComponent = qm.createProject("Acme Library", null, null, null, null, null, true, false);
        Response responseWithComponent = target(V1_COMPONENT + "/project/" + projectWithComponent.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject jsonWithComponent = parseJsonObject(responseWithComponent);
        Assert.assertEquals(200, responseWithComponent.getStatus(), 0);
        Assert.assertEquals(1, jsonWithComponent.size());
        Response responseWithoutComponent = target(V1_COMPONENT + "/project/" + projectWithoutComponent.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject jsonWithoutComponent = parseJsonObject(responseWithoutComponent);
        Assert.assertEquals(200, responseWithoutComponent.getStatus(), 0);
        Assert.assertEquals(0, jsonWithoutComponent.size());
    }

}
