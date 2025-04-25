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

import alpine.common.util.UuidUtil;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

class LicenseResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(LicenseResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @BeforeEach
    public void before() throws Exception {
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultLicenses();
    }

    @Test
    void getLicensesTest() {
        Response response = jersey.target(V1_LICENSE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(757), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(100, json.size());
        Assertions.assertNotNull(json.getJsonObject(0).getString("name"));
        Assertions.assertNotNull(json.getJsonObject(0).getString("licenseText"));
        Assertions.assertNotNull(json.getJsonObject(0).getString("licenseComments"));
        Assertions.assertNotNull(json.getJsonObject(0).getString("licenseId"));
    }

    @Test
    void getLicensesConciseTest() {
        Response response = jersey.target(V1_LICENSE + "/concise").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(757, json.size());
        Assertions.assertNotNull(json.getJsonObject(0).getString("name"));
        Assertions.assertNull(json.getJsonObject(0).getString("licenseText", null));
        Assertions.assertNull(json.getJsonObject(0).getString("licenseComments", null));
        Assertions.assertNotNull(json.getJsonObject(0).getString("licenseId"));
    }

    @Test
    void getLicense() {
        Response response = jersey.target(V1_LICENSE + "/Apache-2.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Apache License 2.0", json.getString("name"));
        Assertions.assertNotNull(json.getString("licenseText", null));
        Assertions.assertNotNull(json.getString("licenseComments", null));
        Assertions.assertNotNull(json.getString("licenseId"));
    }

    @Test
    void getLicenseInvalid() {
        Response response = jersey.target(V1_LICENSE + "/blah").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The license could not be found.", body);
    }

    @Test
    void createCustomLicense() {
        License license = new License();
        license.setName("Acme Example");
        license.setLicenseId("Acme-Example-License");
        Response response = jersey.target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(license, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Acme Example", json.getString("name"));
        Assertions.assertEquals("Acme-Example-License", json.getString("licenseId"));
        Assertions.assertFalse(json.getBoolean("isOsiApproved"));
        Assertions.assertFalse(json.getBoolean("isFsfLibre"));
        Assertions.assertFalse(json.getBoolean("isDeprecatedLicenseId"));
        Assertions.assertTrue(json.getBoolean("isCustomLicense"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    void createCustomLicenseDuplicate() {
        License license = new License();
        license.setName("Apache License 2.0");
        license.setLicenseId("Apache-2.0");
        Response response = jersey.target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(license, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A license with the specified name already exists.", body);
    }

    @Test
    void createCustomLicenseWithoutLicenseId() {
        License license = new License();
        license.setName("Acme Example");
        Response response = jersey.target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(license, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void deleteCustomLicense() {
        License license = new License();
        license.setLicenseId("Acme-Example-License");
        license.setName("Acme Example");
        license.setCustomLicense(true);
        qm.createCustomLicense(license, false);

        Response response = jersey.target(V1_LICENSE + "/" + license.getLicenseId())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
        Assertions.assertTrue(license.isCustomLicense());
    }

    @Test
    void deleteNotCustomLicense() {
        License license1 = new License();
        license1.setLicenseId("Acme-Example-License");
        license1.setName("Acme Example");
        License license2 = qm.createCustomLicense(license1, false);
        license1.setCustomLicense(false);
        Response response = jersey.target(V1_LICENSE + "/" + license1.getLicenseId())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(409, response.getStatus(), 0);
        Assertions.assertFalse(license2.isCustomLicense());
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Only custom licenses can be deleted.", body);
    }
}
