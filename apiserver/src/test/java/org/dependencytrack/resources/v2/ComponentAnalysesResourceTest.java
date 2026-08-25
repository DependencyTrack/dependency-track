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

import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

class ComponentAnalysesResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig());

    @Test
    void shouldCreateAnalysisWithAuditTrail() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");

        final Response response = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "group": "org.acme",
                  "name": "acme-lib",
                  "version": "1.0.0",
                  "license": "Apache-2.0",
                  "details": "curated"
                }
                """.formatted(project.getUuid()));

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        final JsonObject analysis = getAnalysisFromList(project.getUuid(), "acme-lib");
        assertThatJson(analysis.toString()).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-number}",
                  "group": "org.acme",
                  "name": "acme-lib",
                  "version": "1.0.0",
                  "license": "Apache-2.0",
                  "details": "curated"
                }
                """);

        final Response commentsResponse = getComments(analysis.getJsonNumber("id").longValue());
        assertThat(commentsResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(commentsResponse)).isEqualTo(/* language=JSON */ """
                {
                  "comments": [
                    {
                      "timestamp": "${json-unit.any-number}",
                      "commenter": "${json-unit.any-string}",
                      "comment": "License override: not set → Apache-2.0"
                    },
                    {
                      "timestamp": "${json-unit.any-number}",
                      "commenter": "${json-unit.any-string}",
                      "comment": "Details: not set → curated"
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldApplyLicenseToMatchingComponentsImmediately() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        final License apache = createSpdxLicense("Apache-2.0", "Apache License 2.0");
        final Component component = createComponent(project, "org.acme", "acme-lib", "1.0.0", "Unknown License");

        final Response response = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "group": "org.acme",
                  "name": "acme-lib",
                  "version": "1.0.0",
                  "license": "Apache-2.0",
                  "details": "curated"
                }
                """.formatted(project.getUuid()));

        assertThat(response.getStatus()).isEqualTo(204);

        final JsonObject analysis = getAnalysisFromList(project.getUuid(), "acme-lib");
        assertThat(analysis.getString("declared_license")).isEqualTo("Unknown License");

        qm.getPersistenceManager().evictAll();
        final Component updatedComponent = qm.getObjectByUuid(Component.class, component.getUuid());
        assertThat(updatedComponent.getResolvedLicense()).isNotNull();
        assertThat(updatedComponent.getResolvedLicense().getId()).isEqualTo(apache.getId());
        assertThat(updatedComponent.getNotes()).isEqualTo("curated");
    }

    @Test
    void shouldListAnalysesByProject() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        final Project otherProject = qm.createProject("other-app", null, null, null, null, null, null, false);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");

        for (final String componentName : new String[]{"acme-lib-a", "acme-lib-b"}) {
            final Response response = upsertAnalysis(/* language=JSON */ """
                    {
                      "project_uuid": "%s",
                      "name": "%s",
                      "license": "Apache-2.0"
                    }
                    """.formatted(project.getUuid(), componentName));
            assertThat(response.getStatus()).isEqualTo(204);
        }
        final Response otherResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "name": "other-lib",
                  "license": "Apache-2.0"
                }
                """.formatted(otherProject.getUuid()));
        assertThat(otherResponse.getStatus()).isEqualTo(204);

        final Response response = listAnalyses(project.getUuid());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "analyses": [
                            {
                              "id": "${json-unit.any-number}",
                              "name": "acme-lib-a",
                              "license": "Apache-2.0"
                            },
                            {
                              "id": "${json-unit.any-number}",
                              "name": "acme-lib-b",
                              "license": "Apache-2.0"
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldReturn404WhenListingUnknownProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey
                .target("/component-analyses")
                .queryParam("project", UUID.fromString("00000000-0000-0000-0000-000000000001"))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldRecordLicenseTransitionOnUpdate() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");
        createSpdxLicense("MIT", "MIT License");

        final Response firstResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "name": "acme-lib",
                  "license": "Apache-2.0"
                }
                """.formatted(project.getUuid()));
        assertThat(firstResponse.getStatus()).isEqualTo(204);
        final long analysisId = getAnalysisFromList(project.getUuid(), "acme-lib")
                .getJsonNumber("id").longValue();

        final Response secondResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "name": "acme-lib",
                  "license": "MIT"
                }
                """.formatted(project.getUuid()));
        assertThat(secondResponse.getStatus()).isEqualTo(204);

        final JsonObject updatedAnalysis = getAnalysisFromList(project.getUuid(), "acme-lib");
        assertThat(updatedAnalysis.getJsonNumber("id").longValue()).isEqualTo(analysisId);
        assertThat(updatedAnalysis.getString("license")).isEqualTo("MIT");

        final Response commentsResponse = getComments(analysisId);
        assertThat(commentsResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(commentsResponse))
                .node("comments").isArray().anySatisfy(comment -> assertThatJson(comment)
                        .node("comment").isEqualTo("License override: Apache-2.0 → MIT"));
    }

    @Test
    void shouldRestoreDeclaredLicenseWhenOverrideCleared() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");
        final Component component = createComponent(project, "org.acme", "acme-lib", "1.0.0", "Proprietary Foo");

        final Response overrideResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "group": "org.acme",
                  "name": "acme-lib",
                  "version": "1.0.0",
                  "license": "Apache-2.0"
                }
                """.formatted(project.getUuid()));
        assertThat(overrideResponse.getStatus()).isEqualTo(204);
        final long analysisId = getAnalysisFromList(project.getUuid(), "acme-lib")
                .getJsonNumber("id").longValue();

        final Response clearResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "group": "org.acme",
                  "name": "acme-lib",
                  "version": "1.0.0"
                }
                """.formatted(project.getUuid()));
        assertThat(clearResponse.getStatus()).isEqualTo(204);

        final JsonObject clearedAnalysis = getAnalysisFromList(project.getUuid(), "acme-lib");
        assertThat(clearedAnalysis.containsKey("license")).isFalse();
        assertThat(clearedAnalysis.getString("declared_license")).isEqualTo("Proprietary Foo");

        qm.getPersistenceManager().evictAll();
        final Component restoredComponent = qm.getObjectByUuid(Component.class, component.getUuid());
        assertThat(restoredComponent.getResolvedLicense()).isNull();
        assertThat(restoredComponent.getLicense()).isEqualTo("Proprietary Foo");

        final Response commentsResponse = getComments(analysisId);
        assertThat(commentsResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(commentsResponse))
                .node("comments").isArray().anySatisfy(comment -> assertThatJson(comment)
                        .node("comment").isEqualTo("License override: Apache-2.0 → not set"));
    }

    @Test
    void shouldCreateManualComment() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");

        final Response upsertResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "name": "acme-lib",
                  "license": "Apache-2.0"
                }
                """.formatted(project.getUuid()));
        assertThat(upsertResponse.getStatus()).isEqualTo(204);
        final long analysisId = getAnalysisFromList(project.getUuid(), "acme-lib")
                .getJsonNumber("id").longValue();

        final Response createCommentResponse = jersey
                .target("/component-analyses/%d/comments".formatted(analysisId))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "comment": "manually reviewed"
                        }
                        """));
        assertThat(createCommentResponse.getStatus()).isEqualTo(201);
        assertThat(createCommentResponse.getLocation()).isNotNull();
        assertThat(createCommentResponse.getLocation().getPath())
                .endsWith("/component-analyses/%d/comments".formatted(analysisId));

        final Response commentsResponse = getComments(analysisId);
        assertThat(commentsResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(commentsResponse))
                .node("comments").isArray().anySatisfy(comment -> assertThatJson(comment)
                        .node("comment").isEqualTo("manually reviewed"));
    }

    @Test
    void shouldDeleteAnalysis() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);
        createSpdxLicense("Apache-2.0", "Apache License 2.0");

        final Response upsertResponse = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "name": "acme-lib",
                  "license": "Apache-2.0"
                }
                """.formatted(project.getUuid()));
        assertThat(upsertResponse.getStatus()).isEqualTo(204);
        final long analysisId = getAnalysisFromList(project.getUuid(), "acme-lib")
                .getJsonNumber("id").longValue();

        final Response deleteResponse = jersey
                .target("/component-analyses/" + analysisId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(deleteResponse.getStatus()).isEqualTo(204);

        final Response listResponse = listAnalyses(project.getUuid());
        assertThat(listResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(listResponse))
                .node("analyses").isArray().isEmpty();
    }

    @Test
    void shouldReturn404WhenDeletingNonExistentAnalysis() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);

        final Response response = jersey
                .target("/component-analyses/999999")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn403WhenUpsertingWithoutPolicyManagementPermission() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        final Response response = upsertAnalysis(/* language=JSON */ """
                {
                  "project_uuid": "%s",
                  "name": "acme-lib"
                }
                """.formatted(project.getUuid()));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldReturn403WhenListingWithoutViewPortfolioPermission() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT);
        final Project project = qm.createProject("acme-app", null, null, null, null, null, null, false);

        final Response response = listAnalyses(project.getUuid());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    private Response upsertAnalysis(final String requestBody) {
        return jersey
                .target("/component-analyses")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(requestBody));
    }

    private Response listAnalyses(final UUID projectUuid) {
        return jersey
                .target("/component-analyses")
                .queryParam("project", projectUuid)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
    }

    private JsonObject getAnalysisFromList(final UUID projectUuid, final String componentName) {
        final Response response = listAnalyses(projectUuid);
        assertThat(response.getStatus()).isEqualTo(200);
        for (final JsonValue analysis : parseJsonObject(response).getJsonArray("analyses")) {
            if (componentName.equals(analysis.asJsonObject().getString("name"))) {
                return analysis.asJsonObject();
            }
        }
        return fail("No analysis found for component %s", componentName);
    }

    private Response getComments(final long analysisId) {
        return jersey
                .target("/component-analyses/%d/comments".formatted(analysisId))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
    }

    private License createSpdxLicense(final String licenseId, final String name) {
        final var license = new License();
        license.setLicenseId(licenseId);
        license.setName(name);
        return qm.persist(license);
    }

    private Component createComponent(
            final Project project,
            final String group,
            final String name,
            final String version,
            final String declaredLicenseName) {
        final var component = new Component();
        component.setProject(project);
        component.setGroup(group);
        component.setName(name);
        component.setVersion(version);
        component.setLicense(declaredLicenseName);
        return qm.createComponent(component, false);
    }

}
