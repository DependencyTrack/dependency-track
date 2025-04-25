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

import alpine.model.MappedLdapGroup;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.resources.v1.vo.MappedLdapGroupRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.UUID;

class LdapResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(LdapResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    void retrieveLdapGroupsNotEnabledTest() {
        Response response = jersey.target(V1_LDAP + "/groups").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    //@Test TODO: Add integration test to get back actual LDAP groups from a directory server
    public void retrieveLdapGroupsIsEnabledTest() {
    }

    @Test
    void retrieveLdapGroupsTest() {
        qm.createMappedLdapGroup(team, "CN=Developers,OU=R&D,O=Acme");
        qm.createMappedLdapGroup(team, "CN=QA,OU=R&D,O=Acme");
        Response response = jersey.target(V1_LDAP + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(2, json.size());
        Assertions.assertEquals("CN=Developers,OU=R&D,O=Acme", json.getJsonObject(0).getString("dn"));
        Assertions.assertEquals("CN=QA,OU=R&D,O=Acme", json.getJsonObject(1).getString("dn"));
    }

    @Test
    void addMappingTest() {
        MappedLdapGroupRequest request = new MappedLdapGroupRequest(team.getUuid().toString(), "CN=Administrators,OU=R&D,O=Acme");
        Response response = jersey.target(V1_LDAP + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("CN=Administrators,OU=R&D,O=Acme", json.getString("dn"));
    }

    @Test
    void addMappingInvalidTest() {
        MappedLdapGroupRequest request = new MappedLdapGroupRequest(UUID.randomUUID().toString(), "CN=Administrators,OU=R&D,O=Acme");
        Response response = jersey.target(V1_LDAP + "/mapping").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The UUID of the team could not be found.", body);
    }

    @Test
    void deleteMappingTest() {
        MappedLdapGroup mapping = qm.createMappedLdapGroup(team, "CN=Finance,OU=R&D,O=Acme");
        Response response = jersey.target(V1_LDAP + "/mapping/" + mapping.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete(Response.class);
        Assertions.assertEquals(204, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void deleteMappingInvalidTest() {
        Response response = jersey.target(V1_LDAP + "/mapping/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The UUID of the mapping could not be found.", body);
    }
}
