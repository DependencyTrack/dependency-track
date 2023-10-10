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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import us.springett.owasp.riskrating.Level;

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

    @Test
    public void getOwaspRRScoresTest() {
        Response response = target(V1_CALCULATOR + "/owasp")
                .queryParam("vector", "SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1.0, json.getJsonNumber("likelihoodScore").doubleValue(), 0);
        Assert.assertEquals(1.25, json.getJsonNumber("technicalImpactScore").doubleValue(), 0);
        Assert.assertEquals(1.75, json.getJsonNumber("businessImpactScore").doubleValue(), 0);
        Assert.assertEquals(Level.LOW.name(), json.getJsonString("likelihood").getString());
        Assert.assertEquals(Level.LOW.name(), json.getJsonString("technicalImpact").getString());
        Assert.assertEquals(Level.LOW.name(), json.getJsonString("businessImpact").getString());
    }

    @Test
    public void getOwaspScoresInvalidTest() {
        Response response = target(V1_CALCULATOR + "/owasp")
                .queryParam("vector", "foobar")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Provided vector foobar does not match OWASP RR Vector pattern SL:\\d/M:\\d/O:\\d/S:\\d/ED:\\d/EE:\\d/A:\\d/ID:\\d/LC:\\d/LI:\\d/LAV:\\d/LAC:\\d/FD:\\d/RD:\\d/NC:\\d/PV:\\d", body);
    }
}
