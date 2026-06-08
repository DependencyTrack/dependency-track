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
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import alpine.server.resources.GlobalExceptionHandler;
import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publishing.DefaultNotificationPublishersPlugin;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

class NotificationRuleResourceTest extends ResourceTest {

    private static PluginManager pluginManager;

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(NotificationRuleResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bindFactory(() -> pluginManager).to(PluginManager.class);
                        }
                    })
                    .register(GlobalExceptionHandler.class));

    private NotificationPublisher publisher;

    @BeforeAll
    static void beforeAll() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretName -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(org.dependencytrack.notification.api.publishing.NotificationPublisher.class));
        pluginManager.loadPlugins(List.of(new DefaultNotificationPublishersPlugin()));
    }

    @BeforeEach
    void beforeEach() {
        publisher = qm.createNotificationPublisher(
                "Slack",
                "description",
                "slack",
                "templateContent",
                "templateMimeType",
                true);
    }

    @AfterAll
    static void afterAll() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void getAllNotificationRulesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);
        qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        qm.createNotificationRule("Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        qm.createNotificationRule("Rule 3", NotificationScope.SYSTEM, NotificationLevel.ERROR, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(3, json.size());
        Assertions.assertEquals("Rule 1", json.getJsonObject(0).getString("name"));
        Assertions.assertTrue(json.getJsonObject(0).getBoolean("enabled"));
        Assertions.assertEquals("PORTFOLIO", json.getJsonObject(0).getString("scope"));
        Assertions.assertEquals("INFORMATIONAL", json.getJsonObject(0).getString("notificationLevel"));
        Assertions.assertEquals(0, json.getJsonObject(0).getJsonArray("notifyOn").size());
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getJsonObject(0).getString("uuid")));
        Assertions.assertEquals("Slack", json.getJsonObject(0).getJsonObject("publisher").getString("name"));
    }

    @Test
    void createNotificationRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);
        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Example Rule",
                          "notificationLevel": "WARNING",
                          "scope": "SYSTEM",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Example Rule",
                  "enabled": true,
                  "notifyChildren": true,
                  "logSuccessfulPublish": false,
                  "scope": "SYSTEM",
                  "notificationLevel": "WARNING",
                  "projects": [],
                  "tags": [],
                  "teams": [],
                  "notifyOn": [],
                  "publisher": {
                    "name": "Slack",
                    "description": "description",
                    "extensionName": "slack",
                    "templateMimeType": "templateMimeType",
                    "defaultPublisher": true,
                    "uuid": "${json-unit.any-string}"
                  },
                  "publisherConfig": "{\\"destinationUrl\\":\\"https://slack.example.com\\"}",
                  "triggerType": "EVENT",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void createNotificationRuleInvalidPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);
        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Example Rule",
                          "notificationLevel": "WARNING",
                          "scope": "SYSTEM",
                          "publisher": {
                            "uuid": "da3222e6-6041-4423-9452-141fc9c2ea77"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "The UUID of the notification publisher could not be found.");
    }

    @Test
    void updateNotificationRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "notificationLevel": "INFORMATIONAL",
                          "scope": "PORTFOLIO",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObjectBuilder ruleJson = Json.createObjectBuilder(parseJsonObject(response));
        ruleJson.add("name", "Example Rule");
        ruleJson.add("notifyOn", Json.createArrayBuilder().add(NotificationGroup.NEW_VULNERABILITY.name()));

        response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(ruleJson.build().toString()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Example Rule",
                  "enabled": true,
                  "notifyChildren": true,
                  "logSuccessfulPublish": false,
                  "scope": "PORTFOLIO",
                  "notificationLevel": "INFORMATIONAL",
                  "projects": [],
                  "tags": [],
                  "teams": [],
                  "notifyOn": [
                    "NEW_VULNERABILITY"
                  ],
                  "publisher": {
                    "name": "Slack",
                    "description": "description",
                    "extensionName": "slack",
                    "templateMimeType": "templateMimeType",
                    "defaultPublisher": true,
                    "uuid": "${json-unit.any-string}"
                  },
                  "publisherConfig": "{\\"destinationUrl\\":\\"https://slack.example.com\\"}",
                  "triggerType": "EVENT",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void updateNotificationRuleInvalidTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule = qm.detach(NotificationRule.class, rule.getId());
        rule.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The UUID of the notification rule could not be found.", body);
    }

    @Test
    void deleteNotificationRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(rule, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void addProjectToRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Example Rule", json.getString("name"));
        Assertions.assertEquals(1, json.getJsonArray("projects").size());
        Assertions.assertEquals("Acme Example", json.getJsonArray("projects").getJsonObject(0).getString("name"));
        Assertions.assertEquals(project.getUuid().toString(), json.getJsonArray("projects").getJsonObject(0).getString("uuid"));
    }

    @Test
    void addProjectToRuleInvalidRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void addProjectToRuleInvalidScopeTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    void addProjectToRuleInvalidProjectTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void addProjectToRuleDuplicateProjectTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void addProjectToRuleAclTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final NotificationRule rule = qm.createNotificationRule(
                "rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void removeProjectFromRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeProjectFromRuleInvalidRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void removeProjectFromRuleInvalidScopeTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    void removeProjectFromRuleInvalidProjectTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void removeProjectFromRuleDuplicateProjectTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeProjectFromRuleAclTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final NotificationRule rule = qm.createNotificationRule(
                "rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(project));

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void shouldNotLeakInaccessibleProjectsViaGetAllNotificationRulesWhenAclEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final NotificationRule rule = qm.createNotificationRule(
                "Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(accessibleProject, inaccessibleProject));
        qm.persist(rule);

        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$[0].projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    void shouldNotLeakInaccessibleProjectsInAddProjectToRuleResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        enablePortfolioAccessControl();

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final NotificationRule rule = qm.createNotificationRule(
                "Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(inaccessibleProject));
        qm.persist(rule);

        final Response response = jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + accessibleProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    void shouldNotLeakInaccessibleProjectsInUpdateNotificationRuleResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final NotificationRule rule = qm.createNotificationRule(
                "Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(accessibleProject, inaccessibleProject));
        rule.setPublisherConfig("{\"destinationUrl\":\"https://slack.example.com\"}");
        qm.persist(rule);

        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "renamed",
                          "scope": "PORTFOLIO",
                          "level": "INFORMATIONAL",
                          "enabled": true,
                          "notifyChildren": true,
                          "logSuccessfulPublish": false,
                          "notifyOn": [],
                          "tags": [],
                          "publisherConfig": "{\\"destinationUrl\\":\\"https://slack.example.com\\"}"
                        }
                        """.formatted(rule.getUuid())));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    void shouldNotLeakInaccessibleProjectsInAddTeamToRuleResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final NotificationRule rule = qm.createNotificationRule(
                "Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(accessibleProject, inaccessibleProject));
        qm.persist(rule);

        final Team newTeam = qm.createTeam("notify-team");

        final Response response = jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + newTeam.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    void shouldNotLeakInaccessibleProjectsInRemoveTeamFromRuleResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final Team existingTeam = qm.createTeam("notify-team");

        final NotificationRule rule = qm.createNotificationRule(
                "Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(accessibleProject, inaccessibleProject));
        rule.setTeams(Set.of(existingTeam));
        qm.persist(rule);

        final Response response = jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + existingTeam.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    void shouldNotLeakInaccessibleProjectsInRemoveProjectFromRuleResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        enablePortfolioAccessControl();

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final NotificationRule rule = qm.createNotificationRule(
                "Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setProjects(List.of(inaccessibleProject, accessibleProject));
        qm.persist(rule);

        final Response response = jersey
                .target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/project/" + accessibleProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects")
                .isArray()
                .isEmpty();
    }

    @Test
    void addTeamToRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Team team = qm.createTeam("Team Example");
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Example Rule", json.getString("name"));
        Assertions.assertEquals(1, json.getJsonArray("teams").size());
        Assertions.assertEquals("Team Example", json.getJsonArray("teams").getJsonObject(0).getString("name"));
        Assertions.assertEquals(team.getUuid().toString(), json.getJsonArray("teams").getJsonObject(0).getString("uuid"));
    }

    @Test
    void addTeamToRuleInvalidRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Team team = qm.createTeam("Team Example");
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void addTeamToRuleInvalidTeamTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void addTeamToRuleDuplicateTeamTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Team team = qm.createTeam("Team Example");
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<Team> teams = new HashSet<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void addTeamToRuleWithCustomEmailPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);
        final Team team = qm.createTeam("Team Example");
        final NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        final Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publisherUuid", equalTo(publisher.getUuid().toString()))
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .withMatcher("teamUuid", equalTo(team.getUuid().toString()))
                .isEqualTo("""
                        {
                          "name": "Example Rule",
                          "enabled": true,
                          "notifyChildren": true,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "tags": [],
                          "teams": [
                            {
                              "uuid": "${json-unit.matches:teamUuid}",
                              "name": "Team Example",
                              "permissions": []
                            }
                          ],
                          "notifyOn": [],
                          "publisher": {
                            "name": "Slack",
                            "description": "description",
                            "extensionName": "slack",
                            "templateMimeType": "templateMimeType",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.matches:publisherUuid}"
                          },
                          "triggerType": "EVENT",
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);
    }

    @Test
    void removeTeamFromRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Team team = qm.createTeam("Team Example");
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Set<Team> teams = new HashSet<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeTeamFromRuleInvalidRuleTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Team team = qm.createTeam("Team Example");
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void removeTeamFromRuleInvalidTeamTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void removeTeamFromRuleDuplicateTeamTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);
        Team team = qm.createTeam("Team Example");
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void updateNotificationRuleWithTagsTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE, Permissions.SYSTEM_CONFIGURATION_UPDATE);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "notificationLevel": "INFORMATIONAL",
                          "scope": "PORTFOLIO",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);

        // Tag the rule with "foo" and "bar".
        JsonObjectBuilder ruleJson = Json.createObjectBuilder(parseJsonObject(response));
        ruleJson.add("tags", Json.createArrayBuilder()
                .add(Json.createObjectBuilder().add("name", "foo"))
                .add(Json.createObjectBuilder().add("name", "bar")));

        response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(ruleJson.build().toString()));
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString())
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "enabled": true,
                          "notifyChildren": true,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "tags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "bar"
                            }
                          ],
                          "teams": [],
                          "notifyOn": [],
                          "publisher": {
                            "name": "${json-unit.any-string}",
                            "description": "${json-unit.any-string}",
                            "extensionName": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          "publisherConfig": "${json-unit.any-string}",
                          "triggerType": "EVENT",
                          "uuid": "${json-unit.any-string}"
                        }
                        """);

        // Replace the previous tags with only "baz".
        ruleJson = Json.createObjectBuilder(responseJson);
        ruleJson.add("tags", Json.createArrayBuilder()
                .add(Json.createObjectBuilder().add("name", "baz")));

        response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(ruleJson.build().toString()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Rule 1",
                  "enabled": true,
                  "notifyChildren": true,
                  "logSuccessfulPublish": false,
                  "scope": "PORTFOLIO",
                  "notificationLevel": "INFORMATIONAL",
                  "projects": [],
                  "tags": [
                    {
                      "name": "baz"
                    }
                  ],
                  "teams": [],
                  "notifyOn": [],
                  "publisher": {
                    "name": "${json-unit.any-string}",
                    "description": "${json-unit.any-string}",
                    "extensionName": "${json-unit.any-string}",
                    "templateMimeType": "${json-unit.any-string}",
                    "defaultPublisher": true,
                    "uuid": "${json-unit.any-string}"
                  },
                  "publisherConfig": "${json-unit.any-string}",
                  "triggerType": "EVENT",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldUpdateNotificationRuleWithValidFilterExpression() {
        initializeWithPermissions(
                Permissions.SYSTEM_CONFIGURATION_CREATE,
                Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_NOTIFICATION_RULE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "notificationLevel": "INFORMATIONAL",
                          "scope": "PORTFOLIO",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObjectBuilder ruleJson = Json.createObjectBuilder(parseJsonObject(response));
        ruleJson.add("filterExpression", "group == 1");

        response = jersey
                .target(V1_NOTIFICATION_RULE)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(ruleJson.build().toString()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Rule 1",
                  "enabled": true,
                  "notifyChildren": true,
                  "logSuccessfulPublish": false,
                  "scope": "PORTFOLIO",
                  "notificationLevel": "INFORMATIONAL",
                  "projects": [],
                  "tags": [],
                  "teams": [],
                  "notifyOn": [],
                  "publisher": {
                    "name": "Slack",
                    "description": "description",
                    "extensionName": "slack",
                    "templateMimeType": "templateMimeType",
                    "defaultPublisher": true,
                    "uuid": "${json-unit.any-string}"
                  },
                  "publisherConfig": "${json-unit.any-string}",
                  "triggerType": "EVENT",
                  "filterExpression": "group == 1",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldReturnBadRequestWhenFilterExpressionIsInvalid() {
        initializeWithPermissions(
                Permissions.SYSTEM_CONFIGURATION_CREATE,
                Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_NOTIFICATION_RULE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "notificationLevel": "INFORMATIONAL",
                          "scope": "PORTFOLIO",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObjectBuilder ruleJson = Json.createObjectBuilder(parseJsonObject(response));
        ruleJson.add("filterExpression", "invalid %%% expression");

        response = jersey
                .target(V1_NOTIFICATION_RULE)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(ruleJson.build().toString()));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Filter expression is invalid",
                  "errors": [
                    {
                      "line": 1,
                      "column": 9,
                      "message": "${json-unit.any-string}"
                    },
                    {
                      "line": 1,
                      "column": 10,
                      "message": "${json-unit.any-string}"
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldUpdateNotificationRuleWithNullFilterExpression() {
        initializeWithPermissions(
                Permissions.SYSTEM_CONFIGURATION_CREATE,
                Permissions.SYSTEM_CONFIGURATION_UPDATE);

        Response response = jersey
                .target(V1_NOTIFICATION_RULE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "notificationLevel": "INFORMATIONAL",
                          "scope": "PORTFOLIO",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObjectBuilder ruleJson = Json.createObjectBuilder(parseJsonObject(response));
        ruleJson.addNull("filterExpression");

        response = jersey
                .target(V1_NOTIFICATION_RULE)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(ruleJson.build().toString()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Rule 1",
                  "enabled": true,
                  "notifyChildren": true,
                  "logSuccessfulPublish": false,
                  "scope": "PORTFOLIO",
                  "notificationLevel": "INFORMATIONAL",
                  "projects": [],
                  "tags": [],
                  "teams": [],
                  "notifyOn": [],
                  "publisher": {
                    "name": "Slack",
                    "description": "description",
                    "extensionName": "slack",
                    "templateMimeType": "templateMimeType",
                    "defaultPublisher": true,
                    "uuid": "${json-unit.any-string}"
                  },
                  "publisherConfig": "${json-unit.any-string}",
                  "triggerType": "EVENT",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

}
