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
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

class LicenseGroupResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(LicenseGroupResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @Test
    void shouldReturnEmptyListWhenNoGroups() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThatJson(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    void shouldReturnGroupWithoutLicenses() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final LicenseGroup group = qm.createLicenseGroup("Copyleft");

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "name": "Copyleft",
                    "licenses": [],
                    "riskWeight": 0,
                    "uuid": "%s"
                  }
                ]
                """.formatted(group.getUuid()));
    }

    @Test
    void shouldReturnGroupWithLicenses() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final License license = createLicense();
        final LicenseGroup group = qm.createLicenseGroup("Copyleft");
        group.setLicenses(List.of(license));
        qm.persist(group);

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "name": "Copyleft",
                    "licenses": [
                      {
                        "name": "Apache License 2.0",
                        "licenseId": "Apache-2.0",
                        "isOsiApproved": true,
                        "isFsfLibre": true,
                        "isDeprecatedLicenseId": false,
                        "isCustomLicense": false,
                        "uuid": "%s"
                      }
                    ],
                    "riskWeight": 0,
                    "uuid": "%s"
                  }
                ]
                """.formatted(license.getUuid(), group.getUuid()));
    }

    @Test
    void shouldReturnGroupByUuid() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final LicenseGroup group = qm.createLicenseGroup("Copyleft");

        final Response response = jersey
                .target("%s/%s".formatted(V1_LICENSE_GROUP, group.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Copyleft",
                  "licenses": [],
                  "riskWeight": 0,
                  "uuid": "%s"
                }
                """.formatted(group.getUuid()));
    }

    @Test
    void shouldReturn404WhenGroupNotFound() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final Response response = jersey
                .target("%s/%s".formatted(V1_LICENSE_GROUP, UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The license group could not be found.");
    }

    @Test
    void shouldCreateGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Copyleft"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Copyleft",
                  "licenses": [],
                  "riskWeight": 0,
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldReturn409OnDuplicateCreate() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        qm.createLicenseGroup("Copyleft");

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Copyleft"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(getPlainTextBody(response)).isEqualTo("A license group with the specified name already exists.");
    }

    @Test
    void shouldReturn400WhenNameBlankOnCreate() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": ""
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void shouldUpdateGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final LicenseGroup group = qm.createLicenseGroup("Copyleft");

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Permissive"
                        }
                        """.formatted(group.getUuid())));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Permissive",
                  "licenses": [],
                  "riskWeight": 0,
                  "uuid": "%s"
                }
                """.formatted(group.getUuid()));
    }

    @Test
    void shouldReturn404OnUpdateUnknownGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Permissive"
                        }
                        """.formatted(UUID.randomUUID())));

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The license group could not be found.");
    }

    @Test
    void shouldDeleteGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);

        final LicenseGroup group = qm.createLicenseGroup("Copyleft");

        final Response response = jersey
                .target("%s/%s".formatted(V1_LICENSE_GROUP, group.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    void shouldReturn404OnDeleteUnknown() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);

        final Response response = jersey
                .target("%s/%s".formatted(V1_LICENSE_GROUP, UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the license group could not be found.");
    }

    @Test
    void shouldAddLicenseToGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final License license = createLicense();
        final LicenseGroup group = qm.createLicenseGroup("Copyleft");
        group.setLicenses(new ArrayList<>());
        qm.persist(group);

        final Response response = jersey
                .target("%s/%s/license/%s".formatted(V1_LICENSE_GROUP, group.getUuid(), license.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Copyleft",
                  "licenses": [
                    {
                      "name": "Apache License 2.0",
                      "licenseId": "Apache-2.0",
                      "isOsiApproved": true,
                      "isFsfLibre": true,
                      "isDeprecatedLicenseId": false,
                      "isCustomLicense": false,
                      "uuid": "%s"
                    }
                  ],
                  "riskWeight": 0,
                  "uuid": "%s"
                }
                """.formatted(license.getUuid(), group.getUuid()));
    }

    @Test
    void shouldReturn304WhenLicenseAlreadyInGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final License license = createLicense();
        final LicenseGroup group = qm.createLicenseGroup("Copyleft");
        group.setLicenses(new ArrayList<>(List.of(license)));
        qm.persist(group);

        final Response response = jersey
                .target("%s/%s/license/%s".formatted(V1_LICENSE_GROUP, group.getUuid(), license.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        assertThat(response.getStatus()).isEqualTo(304);
    }

    @Test
    void shouldReturn404OnAddWhenGroupMissing() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final License license = createLicense();

        final Response response = jersey
                .target("%s/%s/license/%s".formatted(V1_LICENSE_GROUP, UUID.randomUUID(), license.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The license group could not be found.");
    }

    @Test
    void shouldReturn404OnAddWhenLicenseMissing() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final LicenseGroup group = qm.createLicenseGroup("Copyleft");

        final Response response = jersey
                .target("%s/%s/license/%s".formatted(V1_LICENSE_GROUP, group.getUuid(), UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The license could not be found.");
    }

    @Test
    void shouldRemoveLicenseFromGroup() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final License license = createLicense();
        final LicenseGroup group = qm.createLicenseGroup("Copyleft");
        group.setLicenses(List.of(license));
        qm.persist(group);

        final Response response = jersey
                .target("%s/%s/license/%s".formatted(V1_LICENSE_GROUP, group.getUuid(), license.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Copyleft",
                  "licenses": [],
                  "riskWeight": 0,
                  "uuid": "%s"
                }
                """.formatted(group.getUuid()));
    }

    @Test
    void shouldReturn304WhenRemovingNonMember() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final License license = createLicense();
        final LicenseGroup group = qm.createLicenseGroup("Copyleft");
        group.setLicenses(new ArrayList<>());
        qm.persist(group);

        final Response response = jersey
                .target("%s/%s/license/%s".formatted(V1_LICENSE_GROUP, group.getUuid(), license.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(304);
    }

    @Test
    void shouldReturn403WhenListingUnauthorized() {
        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldReturn403WhenCreatingUnauthorized() {
        final Response response = jersey
                .target(V1_LICENSE_GROUP)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Copyleft"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    private License createLicense() {
        final License license = new License();
        license.setName("Apache License 2.0");
        license.setLicenseId("Apache-2.0");
        license.setText("license text");
        license.setTemplate("license template");
        license.setHeader("license header");
        license.setComment("license comment");
        license.setOsiApproved(true);
        license.setFsfLibre(true);
        license.setDeprecatedLicenseId(false);
        license.setCustomLicense(false);
        license.setSeeAlso("https://example.org/apache-2.0");
        return qm.persist(license);
    }

}
