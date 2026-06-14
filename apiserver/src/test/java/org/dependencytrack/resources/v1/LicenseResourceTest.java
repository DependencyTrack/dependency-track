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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class LicenseResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(LicenseResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @BeforeEach
    @Override
    public void before() throws Exception {
        super.before();

        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultLicenses);
    }

    @Test
    public void shouldReturnFullLicenseJsonForKnownSpdxIdentifier() {
        final Response response = jersey
                .target(V1_LICENSE + "/Apache-2.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        final String body = getPlainTextBody(response);
        assertThatJson(body)
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Apache License 2.0",
                          "licenseId": "Apache-2.0",
                          "licenseText": "${json-unit.any-string}",
                          "standardLicenseTemplate": "${json-unit.any-string}",
                          "standardLicenseHeader": "${json-unit.any-string}",
                          "licenseComments": "${json-unit.any-string}",
                          "isOsiApproved": true,
                          "isFsfLibre": true,
                          "isDeprecatedLicenseId": false,
                          "isCustomLicense": false,
                          "seeAlso": "${json-unit.ignore}",
                          "licenseGroups": [],
                          "uuid": "${json-unit.any-string}"
                        }
                        """);
        assertThatJson(body).node("seeAlso").isArray().isNotEmpty();
    }

    @Test
    public void shouldTruncateLicenseGroupsToUuidAndName() {
        // NB: The legacy JDO-backed response embedded the entire LicenseGroup entity
        // (including licenses, riskWeight, etc.). With the migration to dedicated DTOs,
        // we truncated it to only UUID and name.

        final License license = qm.getLicense("Apache-2.0");
        final LicenseGroup group = qm.createLicenseGroup("Copyleft");
        group.setLicenses(List.of(license));
        qm.persist(group);

        final Response response = jersey
                .target(V1_LICENSE + "/Apache-2.0")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .node("licenseGroups")
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "uuid": "${json-unit.any-string}",
                            "name": "Copyleft"
                          }
                        ]
                        """);
    }

    @Test
    public void shouldReturn404WhenLicenseIdDoesNotExist() {
        final Response response = jersey
                .target(V1_LICENSE + "/blah")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The license could not be found.");
    }

    @Test
    public void shouldReturnPaginatedFullLicenseListing() {
        final Response response = jersey
                .target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("811");
        final String body = getPlainTextBody(response);
        assertThatJson(body).isArray().hasSize(100);
        assertThatJson(body)
                .node("[0]")
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "${json-unit.any-string}",
                          "licenseId": "${json-unit.any-string}",
                          "licenseText": "${json-unit.ignore}",
                          "licenseComments": "${json-unit.ignore}",
                          "isOsiApproved": "${json-unit.ignore}",
                          "isFsfLibre": "${json-unit.ignore}",
                          "isDeprecatedLicenseId": "${json-unit.ignore}",
                          "isCustomLicense": false,
                          "seeAlso": "${json-unit.ignore}",
                          "licenseGroups": "${json-unit.ignore}",
                          "uuid": "${json-unit.any-string}"
                        }
                        """);
    }

    @Test
    public void shouldReturnConciseLicenseListingWithoutClobFields() {
        final Response response = jersey
                .target(V1_LICENSE + "/concise")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        final String body = getPlainTextBody(response);
        assertThatJson(body).isArray().hasSize(811);
        assertThatJson(body)
                .node("[0]")
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "${json-unit.any-string}",
                          "licenseId": "${json-unit.any-string}",
                          "isOsiApproved": "${json-unit.ignore}",
                          "isFsfLibre": "${json-unit.ignore}",
                          "isDeprecatedLicenseId": "${json-unit.ignore}",
                          "isCustomLicense": false,
                          "uuid": "${json-unit.any-string}"
                        }
                        """);
    }

    @Test
    public void shouldRoundTripAllOptionalFieldsOnCreate() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        final Response response = jersey
                .target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Acme Example",
                          "licenseId": "Acme-Example-License",
                          "licenseText": "All rights reserved.",
                          "standardLicenseHeader": "Copyright (c) Acme",
                          "standardLicenseTemplate": "<<beginOptional>>Acme<<endOptional>>",
                          "licenseComments": "Internal use only.",
                          "seeAlso": ["https://acme.example/a", "https://acme.example/b"],
                          "isOsiApproved": true,
                          "isFsfLibre": true,
                          "isDeprecatedLicenseId": true
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Acme Example",
                          "licenseId": "Acme-Example-License",
                          "licenseText": "All rights reserved.",
                          "standardLicenseHeader": "Copyright (c) Acme",
                          "standardLicenseTemplate": "<<beginOptional>>Acme<<endOptional>>",
                          "licenseComments": "Internal use only.",
                          "seeAlso": ["https://acme.example/a", "https://acme.example/b"],
                          "isOsiApproved": true,
                          "isFsfLibre": true,
                          "isDeprecatedLicenseId": true,
                          "isCustomLicense": true,
                          "licenseGroups": [],
                          "uuid": "${json-unit.any-string}"
                        }
                        """);
    }

    @Test
    public void shouldForceCustomLicenseFlagOnCreate() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        final Response response = jersey
                .target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Sneaky Example",
                          "licenseId": "Sneaky-Example-License",
                          "isCustomLicense": false
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .node("isCustomLicense")
                .isEqualTo(true);
    }

    @Test
    public void shouldReject400WhenCreatingLicenseWithoutName() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        final Response response = jersey
                .target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "licenseId": "Acme-Example-License"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    public void shouldReject400WhenCreatingLicenseWithoutLicenseId() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        final Response response = jersey
                .target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Acme Example"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    public void shouldReject409WhenLicenseAlreadyExists() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        final Response response = jersey
                .target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Apache License 2.0",
                          "licenseId": "Apache-2.0"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response))
                .isEqualTo("A license with the specified licenseId already exists.");
    }

    @Test
    public void shouldDeleteCustomLicense() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        final License license = new License();
        license.setLicenseId("Acme-Example-License");
        license.setName("Acme Example");
        license.setCustomLicense(true);
        qm.createCustomLicense(license, false);

        final Response response = jersey
                .target(V1_LICENSE + "/Acme-Example-License")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    public void shouldReject409WhenDeletingNonCustomLicense() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        final Response response = jersey
                .target(V1_LICENSE + "/Apache-2.0")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("Only custom licenses can be deleted.");
    }

    @Test
    public void shouldReturn404WhenDeletingUnknownLicense() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        final Response response = jersey
                .target(V1_LICENSE + "/does-not-exist")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The license could not be found.");
    }

}
