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

import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;

public class IntegrationResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(IntegrationResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Before
    public void before() throws Exception {
        super.before();
        qm.createConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName(),
                "Maven;npm;Maven",
                IConfigProperty.PropertyType.STRING,
                "List of ecosystems");
        qm.createConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(),
                VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName(),
                "https://osv-vulnerabilities.storage.googleapis.com/",
                IConfigProperty.PropertyType.URL,
                "OSV Base URL");
    }

    @Test
    public void getEcosystemsTest() {
        Response response = jersey.target(V1_OSV_ECOSYSTEM).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertFalse(json.isEmpty());
        var total = json.size();

        response = jersey.target(V1_OSV_ECOSYSTEM + "/inactive").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(total-2, json.size());
    }
}
