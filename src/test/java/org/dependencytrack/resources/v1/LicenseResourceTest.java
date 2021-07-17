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

import alpine.filters.ApiFilter;
import alpine.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.Response;

public class LicenseResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(LicenseResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Before
    public void loadDefaultLicenses() {
        DefaultObjectGenerator dog = new DefaultObjectGenerator();
        dog.contextInitialized(null);
    }

    @Test
    public void getLicensesTest() {
        Response response = target(V1_LICENSE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(489), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertNotNull(json.getJsonObject(0).getString("name"));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseText"));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseComments"));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseId"));
    }

    @Test
    public void getLicensesConciseTest() {
        Response response = target(V1_LICENSE + "/concise").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(489, json.size());
        Assert.assertNotNull(json.getJsonObject(0).getString("name"));
        Assert.assertNull(json.getJsonObject(0).getString("licenseText", null));
        Assert.assertNull(json.getJsonObject(0).getString("licenseComments", null));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseId"));
    }

    @Test
    public void getLicense() {
        Response response = target(V1_LICENSE + "/Apache-2.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Apache License 2.0", json.getString("name"));
        Assert.assertNotNull(json.getString("licenseText", null));
        Assert.assertNotNull(json.getString("licenseComments", null));
        Assert.assertNotNull(json.getString("licenseId"));
    }

    @Test
    public void getLicenseInvalid() {
        Response response = target(V1_LICENSE + "/blah").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The license could not be found.", body);
    }
}
