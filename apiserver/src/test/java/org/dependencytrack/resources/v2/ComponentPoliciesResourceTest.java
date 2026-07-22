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

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.jdbi.ComponentPolicyDao;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;
import java.util.Optional;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ComponentPoliciesResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig());

    @Test
    void shouldCreateComponentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");

        final Response response = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-curation",
                          "description": "Curates the license of acme-lib",
                          "condition": "component.name == \\"acme-lib\\"",
                          "license": "Apache-2.0",
                          "details": "curated by policy",
                          "enabled": true,
                          "priority": 5
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(getPlainTextBody(response)).isEmpty();
        assertThat(response.getLocation()).isNotNull();
        assertThat(response.getLocation().getPath()).matches(".*/component-policies/\\d+$");

        final Response listResponse = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(listResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(listResponse)).isEqualTo(/* language=JSON */ """
                {
                  "policies": [
                    {
                      "id": "${json-unit.any-number}",
                      "name": "acme-curation",
                      "description": "Curates the license of acme-lib",
                      "author": "${json-unit.any-string}",
                      "enabled": true,
                      "priority": 5,
                      "condition": "component.name == \\"acme-lib\\"",
                      "license": "Apache-2.0",
                      "details": "curated by policy"
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldRejectCreateWithInvalidCelCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "broken-condition",
                          "condition": "doesNotExist == true"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .node("detail").isString().startsWith("Invalid CEL condition");
        final List<ComponentPolicyDao.ComponentPolicy> policies = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getAll());
        assertThat(policies).isEmpty();
    }

    @Test
    void shouldNotCreatePolicyWithUnknownLicense() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "unknown-license-policy",
                          "condition": "component.name == \\"acme-lib\\"",
                          "license": "No-Such-License-1.0"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        final List<ComponentPolicyDao.ComponentPolicy> policies = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getAll());
        assertThat(policies).isEmpty();
    }

    @Test
    void shouldListComponentPoliciesInEvaluationOrder() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        inJdbiTransaction(handle -> {
            final var dao = new ComponentPolicyDao(handle);
            dao.create("second-policy", null, "tester", true, 2,
                    "component.name == \"bar\"", null, null, null, null);
            return dao.create("first-policy", null, "tester", false, 1,
                    "component.name == \"foo\"", null, null, null, null);
        });

        final Response response = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "policies": [
                    {
                      "id": "${json-unit.any-number}",
                      "name": "first-policy",
                      "author": "tester",
                      "enabled": false,
                      "priority": 1,
                      "condition": "component.name == \\"foo\\""
                    },
                    {
                      "id": "${json-unit.any-number}",
                      "name": "second-policy",
                      "author": "tester",
                      "enabled": true,
                      "priority": 2,
                      "condition": "component.name == \\"bar\\""
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldUpdateComponentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        createSpdxLicense("MIT", "MIT License");

        final long policyId = inJdbiTransaction(handle -> new ComponentPolicyDao(handle).create(
                "acme-curation", null, "tester", true, 0,
                "component.name == \"acme-lib\"", null, null, null, null));

        final Response response = jersey
                .target("/component-policies/" + policyId)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-curation-updated",
                          "description": "now with a license",
                          "condition": "component.group == \\"org.acme\\"",
                          "license": "MIT",
                          "enabled": false,
                          "priority": 7
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        final Response listResponse = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(listResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(listResponse)).isEqualTo(/* language=JSON */ """
                {
                  "policies": [
                    {
                      "id": %d,
                      "name": "acme-curation-updated",
                      "description": "now with a license",
                      "author": "tester",
                      "enabled": false,
                      "priority": 7,
                      "condition": "component.group == \\"org.acme\\"",
                      "license": "MIT"
                    }
                  ]
                }
                """.formatted(policyId));

        final Optional<ComponentPolicyDao.ComponentPolicy> updated = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getById(policyId));
        assertThat(updated).isPresent();
        assertThat(updated.get().name()).isEqualTo("acme-curation-updated");
        assertThat(updated.get().enabled()).isFalse();
        assertThat(updated.get().priority()).isEqualTo(7);
    }

    @Test
    void shouldReturn404WhenUpdatingNonExistentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey
                .target("/component-policies/999999")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "does-not-exist",
                          "condition": "component.name == \\"foo\\""
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldDeleteComponentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final long policyId = inJdbiTransaction(handle -> new ComponentPolicyDao(handle).create(
                "to-be-deleted", null, "tester", true, 0,
                "component.name == \"foo\"", null, null, null, null));

        final Response response = jersey
                .target("/component-policies/" + policyId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        final Optional<ComponentPolicyDao.ComponentPolicy> deleted = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getById(policyId));
        assertThat(deleted).isEmpty();
    }

    @Test
    void shouldReturn404WhenDeletingNonExistentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey
                .target("/component-policies/999999")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn403WhenMissingPolicyManagementPermission() {
        initializeWithPermissions();

        final Response listResponse = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(listResponse.getStatus()).isEqualTo(403);

        final Response createResponse = jersey
                .target("/component-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "not-allowed",
                          "condition": "component.name == \\"foo\\""
                        }
                        """));
        assertThat(createResponse.getStatus()).isEqualTo(403);
    }

    private License createSpdxLicense(final String licenseId, final String name) {
        final var license = new License();
        license.setLicenseId(licenseId);
        license.setName(name);
        return qm.persist(license);
    }

}
