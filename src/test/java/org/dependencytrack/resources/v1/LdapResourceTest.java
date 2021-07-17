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
import alpine.model.MappedLdapGroup;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.resources.v1.vo.MappedLdapGroupRequest;
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

public class LdapResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(LdapResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void retrieveLdapGroupsNotEnabledTest() {
        Response response = target(V1_LDAP + "/groups").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    //@Test TODO: Add integration test to get back actual LDAP groups from a directory server
    public void retrieveLdapGroupsIsEnabledTest() {
    }

    @Test
    public void retrieveLdapGroupsTest() {
        qm.createMappedLdapGroup(team, "CN=Developers,OU=R&D,O=Acme");
        qm.createMappedLdapGroup(team, "CN=QA,OU=R&D,O=Acme");
        Response response = target(V1_LDAP + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(2, json.size());
        Assert.assertEquals("CN=Developers,OU=R&D,O=Acme", json.getJsonObject(0).getString("dn"));
        Assert.assertEquals("CN=QA,OU=R&D,O=Acme", json.getJsonObject(1).getString("dn"));
    }

    @Test
    public void addMappingTest() {
        MappedLdapGroupRequest request = new MappedLdapGroupRequest(team.getUuid().toString(), "CN=Administrators,OU=R&D,O=Acme");
        Response response = target(V1_LDAP + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("CN=Administrators,OU=R&D,O=Acme", json.getString("dn"));
    }

    @Test
    public void addMappingInvalidTest() {
        MappedLdapGroupRequest request = new MappedLdapGroupRequest(UUID.randomUUID().toString(), "CN=Administrators,OU=R&D,O=Acme");
        Response response = target(V1_LDAP + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the team could not be found.", body);
    }

    @Test
    public void deleteMappingTest() {
        MappedLdapGroup mapping = qm.createMappedLdapGroup(team, "CN=Finance,OU=R&D,O=Acme");
        Response response = target(V1_LDAP + "/mapping/" + mapping.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void deleteMappingInvalidTest() {
        Response response = target(V1_LDAP + "/mapping/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the mapping could not be found.", body);
    }
}
