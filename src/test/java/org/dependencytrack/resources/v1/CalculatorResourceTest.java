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
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonObject;
import javax.ws.rs.core.Response;

public class CalculatorResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(CalculatorResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getCvssScoresV3Test() {
        Response response = target(V1_CALCULATOR + "/cvss")
                .queryParam("vector", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(9.8, json.getJsonNumber("baseScore").doubleValue(), 0);
        Assert.assertEquals(5.9, json.getJsonNumber("impactSubScore").doubleValue(), 0);
        Assert.assertEquals(3.9, json.getJsonNumber("exploitabilitySubScore").doubleValue(), 0);
    }

    @Test
    public void getCvssScoresV2Test() {
        Response response = target(V1_CALCULATOR + "/cvss")
                .queryParam("vector", "(AV:N/AC:L/Au:N/C:P/I:P/A:P)")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(7.5, json.getJsonNumber("baseScore").doubleValue(), 0);
        Assert.assertEquals(6.4, json.getJsonNumber("impactSubScore").doubleValue(), 0);
        Assert.assertEquals(10.0, json.getJsonNumber("exploitabilitySubScore").doubleValue(), 0);
    }

    @Test
    public void getCvssScoresInvalidTest() {
        Response response = target(V1_CALCULATOR + "/cvss")
                .queryParam("vector", "foobar")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("An invalid CVSSv2 or CVSSv3 vector submitted.", body);
    }
}
