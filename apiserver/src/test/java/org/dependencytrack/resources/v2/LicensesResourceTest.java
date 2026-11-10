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
package org.dependencytrack.resources.v2;

import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;

import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

class LicensesResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    @Test
    void shouldReturnMultipleResolvedLicenses() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = prepareProject();
        final Component component = prepareComponent(project);

        final var apache = new License();
        apache.setLicenseId("Apache-2.0");
        apache.setName("Apache License 2.0");
        qm.persist(apache);

        final var mit = new License();
        mit.setLicenseId("MIT");
        mit.setName("MIT License");
        qm.persist(mit);

        qm.getPersistenceManager().flush();

        useJdbiHandle(handle -> handle.createUpdate("""
                INSERT INTO "COMPONENTLICENSES" (
                    "COMPONENT_ID",
                    "LICENSE_ID",
                    "LICENSE_URL",
                    "ORDINALITY",
                    "ACKNOWLEDGEMENT"
                )
                VALUES
                    (:componentId, :apacheId, :apacheUrl, 1, 'DECLARED'),
                    (:componentId, :mitId, :mitUrl, 2, 'DECLARED')
                """)
                .bind("componentId", component.getId())
                .bind("apacheId", apache.getId())
                .bind("apacheUrl", "https://www.apache.org/licenses/LICENSE-2.0")
                .bind("mitId", mit.getId())
                .bind("mitUrl", "https://opensource.org/license/mit")
                .execute());

        final Response response = jersey.target("/licenses/" + component.getUuid())
                .queryParam("limit", 100)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);

        assertThatJson(getPlainTextBody(response))
                .inPath("$.items")
                .isArray()
                .containsExactly(/* language=JSON */ """
            {
                "resolved_license": {
                    "name": "Apache License 2.0",
                    "license_id": "Apache-2.0",
                    "uuid": "${json-unit.any-string}",
                    "osi_approved": false,
                    "fsf_libre": false,
                    "custom_license": false
                },
                "license_url": "https://www.apache.org/licenses/LICENSE-2.0",
                "ordinality": 1,
                "acknowledgement": "DECLARED"
            }
            """, /* language=JSON */ """
            {
                "resolved_license": {
                    "name": "MIT License",
                    "license_id": "MIT",
                    "uuid": "${json-unit.any-string}",
                    "osi_approved": false,
                    "fsf_libre": false,
                    "custom_license": false
                },
                "license_url": "https://opensource.org/license/mit",
                "ordinality": 2,
                "acknowledgement": "DECLARED"
            }
        """);
    }

    @Test
    void shouldReturnUnresolvedLicenses() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = prepareProject();
        final Component component = prepareComponent(project);

        useJdbiHandle(handle ->
                handle.createUpdate("""
                INSERT INTO "COMPONENTLICENSES" (
                    "COMPONENT_ID",
                    "LICENSE",
                    "ORDINALITY",
                    "ACKNOWLEDGEMENT"
                )
                VALUES
                    (:componentId, 'Custom License 1', 1, 'DECLARED'),
                    (:componentId, 'Custom License 2', 2, 'DECLARED')
                """).bind("componentId", component.getId()).execute());

        final Response response = jersey.target("/licenses/" + component.getUuid())
                .queryParam("limit", 100)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);

        assertThatJson(getPlainTextBody(response))
                .inPath("$.items")
                .isArray()
                .containsExactly(/* language=JSON */ """
            {
                "license": "Custom License 1",
                "ordinality": 1,
                "acknowledgement": "DECLARED"
            }
            """, /* language=JSON */ """
            {
                "license": "Custom License 2",
                "ordinality": 2,
                "acknowledgement": "DECLARED"
            }
        """);
    }

    @Test
    void shouldReturnLicenseExpression() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = prepareProject();
        final Component component = prepareComponent(project);

        useJdbiHandle(handle ->
                handle.createUpdate("""
                INSERT INTO "COMPONENTLICENSES" (
                    "COMPONENT_ID",
                    "LICENSE_EXPRESSION",
                    "ORDINALITY",
                    "ACKNOWLEDGEMENT"
                )
                VALUES
                    (:componentId, 'EPL-2.0 OR GPL-2.0', 1, 'DECLARED')
                """).bind("componentId", component.getId()).execute());

        final Response response = jersey.target("/licenses/" + component.getUuid())
                .queryParam("limit", 100)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);

        assertThatJson(getPlainTextBody(response)).inPath("$.items").isArray().containsExactly(/* language=JSON */ """
            {
                "license_expression": "EPL-2.0 OR GPL-2.0",
                "ordinality": 1,
                "acknowledgement": "DECLARED"
            }
        """);
    }

    @Test
    void shouldReturnNotFoundForUnknownComponent() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final UUID uuid = UUID.randomUUID();
        final Response response = jersey.target("/licenses/" + uuid)
                .queryParam("limit", 100)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
    }

    @Test
    void shouldReturnForbiddenWithoutViewPortfolioPermission() {

        final var project = prepareProject();
        final Component component = prepareComponent(project);

        final Response response = jersey.target("/licenses/" + component.getUuid())
                .queryParam("limit", 100)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
    }

    @Test
    void shouldPaginateComponentLicenses() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = prepareProject();
        final Component component = prepareComponent(project);

        useJdbiHandle(handle ->
                handle.createUpdate("""
                INSERT INTO "COMPONENTLICENSES" (
                    "COMPONENT_ID",
                    "LICENSE",
                    "ORDINALITY",
                    "ACKNOWLEDGEMENT"
                )
                VALUES
                    (:componentId, 'License 1', 1, 'DECLARED'),
                    (:componentId, 'License 2', 2, 'DECLARED'),
                    (:componentId, 'License 3', 3, 'DECLARED')
                """).bind("componentId", component.getId()).execute());

        final Response firstResponse = jersey.target("/licenses/" + component.getUuid())
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(firstResponse.getStatus()).isEqualTo(200);

        final JsonObject firstJson = parseJsonObject(firstResponse);
        assertThat(firstJson.getJsonArray("items")).hasSize(2);
        assertThat(firstJson.getJsonObject("total").getInt("count")).isEqualTo(3);
        assertThat(firstJson.containsKey("next_page_token")).isTrue();
        assertThatJson(firstJson.toString()).inPath("$.items[0].license").isEqualTo("License 1");
        assertThatJson(firstJson.toString()).inPath("$.items[1].license").isEqualTo("License 2");

        final String nextPageToken = firstJson.getString("next_page_token");

        Response secondResponse = jersey.target("/licenses/" + component.getUuid())
                .queryParam("limit", 2)
                .queryParam("page_token", nextPageToken)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(secondResponse.getStatus()).isEqualTo(200);

        final JsonObject secondJson = parseJsonObject(secondResponse);
        assertThat(secondJson.getJsonArray("items")).hasSize(1);
        assertThat(secondJson.getJsonObject("total").getInt("count")).isEqualTo(3);
        assertThat(secondJson.containsKey("next_page_token")).isFalse();

        assertThatJson(secondJson.toString()).inPath("$.items[0].license").isEqualTo("License 3");
    }

    private Project prepareProject() {
        return qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);
    }

    private Component prepareComponent(final Project project) {
        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.acme");
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);
        qm.getPersistenceManager().flush();
        return component;
    }
}
