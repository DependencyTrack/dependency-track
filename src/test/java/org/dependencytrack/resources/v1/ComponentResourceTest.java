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
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
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
import java.util.UUID;

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
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        for (int i=0; i<1000; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));
            qm.createComponent(component, false);
        }
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(405, response.getStatus()); // No longer prohibited in DT 4.0+
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

}
