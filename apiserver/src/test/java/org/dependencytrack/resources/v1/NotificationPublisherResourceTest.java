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
import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.DefaultNotificationPublisherInitializer;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publishing.DefaultNotificationPublishersPlugin;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.dependencytrack.resources.v1.vo.UpdateNotificationPublisherRequest;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;

import java.net.http.HttpClient;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

class NotificationPublisherResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);
    private static PluginManager pluginManager;

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(NotificationPublisherResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bindFactory(() -> pluginManager).to(PluginManager.class);
                            bindFactory(() -> DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @BeforeEach
    void resetDexEngineMock() {
        reset(DEX_ENGINE_MOCK);
    }

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

    @AfterAll
    static void afterAll() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void getAllNotificationPublishersTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "name": "Console",
                            "description": "Default Console publisher",
                            "extensionName": "console",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Email",
                            "description": "Default Email publisher",
                            "extensionName": "email",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Jira",
                            "description": "Default Jira publisher",
                            "extensionName": "jira",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Kafka",
                            "description": "Default Kafka publisher",
                            "extensionName": "kafka",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Mattermost",
                            "description": "Default Mattermost publisher",
                            "extensionName": "mattermost",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Msteams",
                            "description": "Default Msteams publisher",
                            "extensionName": "msteams",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Slack",
                            "description": "Default Slack publisher",
                            "extensionName": "slack",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Webex",
                            "description": "Default Webex publisher",
                            "extensionName": "webex",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          {
                            "name": "Webhook",
                            "description": "Default Webhook publisher",
                            "extensionName": "webhook",
                            "template": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          }
                        ]
                        """);
    }

    @Test
    void createNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Example Publisher",
                          "description": "Publisher description",
                          "extensionName": "slack",
                          "template": "template",
                          "templateMimeType": "application/json"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Example Publisher",
                  "description": "Publisher description",
                  "extensionName": "slack",
                  "template": "template",
                  "templateMimeType": "application/json",
                  "defaultPublisher": false,
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void createNotificationPublisherWithExistingNameTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_CREATE);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "Slack",
                          "extensionName": "slack",
                          "template": "template",
                          "templateMimeType": "application/json"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "The notification with the name Slack already exist");
    }

    @Test
    void updateNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                "slack", "template", "text/html",
                false
        );
        notificationPublisher.setName("Updated Publisher name");
        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "Updated Publisher name",
                  "description": "Publisher description",
                  "extensionName": "slack",
                  "template": "template",
                  "templateMimeType": "text/html",
                  "defaultPublisher": false,
                  "uuid": "%s"
                }
                """.formatted(notificationPublisher.getUuid()));
    }

    @Test
    void updateUnknownNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                "slack", "template", "text/html",
                false
        );
        notificationPublisher = qm.detach(NotificationPublisher.class, notificationPublisher.getId());
        notificationPublisher.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The UUID of the notification publisher could not be found.", body);
    }

    @Test
    void updateExistingDefaultNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final NotificationPublisher slackPublisher = qm.getNotificationPublisher("Slack");
        assertThat(slackPublisher).isNotNull();

        final var updateRequest = new UpdateNotificationPublisherRequest(
                "foo",
                slackPublisher.getExtensionName(),
                slackPublisher.getDescription(),
                slackPublisher.getTemplate(),
                slackPublisher.getTemplateMimeType(),
                slackPublisher.getUuid());

        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(updateRequest));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "The modification of a default publisher is forbidden");
    }

    @Test
    void updateNotificationPublisherWithNameOfAnotherNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher",
                "description",
                "slack",
                "template",
                "text/html",
                false);

        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "Slack",
                          "description": "description",
                          "extensionName": "slack",
                          "template": "template",
                          "templateMimeType": "templateMimeType",
                          "uuid": "%s"
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "An existing publisher with the name 'Slack' already exist");
    }

    @Test
    void updateNotificationPublisherWithInvalidExtensionNameTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final NotificationPublisher slackPublisher = qm.getNotificationPublisher("Slack");
        assertThat(slackPublisher).isNotNull();

        final var updateRequest = new UpdateNotificationPublisherRequest(
                slackPublisher.getName(),
                "unknown",
                slackPublisher.getDescription(),
                slackPublisher.getTemplate(),
                slackPublisher.getTemplateMimeType(),
                slackPublisher.getUuid());

        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(updateRequest));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "No extension with name 'unknown' exists");
    }

    @Test
    void deleteNotificationPublisherWithNoRulesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                "slack", "template", "text/html",
                false
        );
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + publisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
        Assertions.assertNull(qm.getObjectByUuid(NotificationPublisher.class, publisher.getUuid()));
    }

    @Test
    void deleteNotificationPublisherWithLinkedNotificationRulesTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                "slack", "template", "text/html",
                false
        );
        NotificationRule firstRule = qm.createNotificationRule("Example Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        NotificationRule secondRule = qm.createNotificationRule("Example Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + publisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
        Assertions.assertNull(qm.getObjectByUuid(NotificationPublisher.class, publisher.getUuid()));
        Assertions.assertNull(qm.getObjectByUuid(NotificationRule.class, firstRule.getUuid()));
        Assertions.assertNull(qm.getObjectByUuid(NotificationRule.class, secondRule.getUuid()));
    }

    @Test
    void deleteUnknownNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void deleteDefaultNotificationPublisherTest() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_DELETE);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final NotificationPublisher slackPublisher = qm.getNotificationPublisher("Slack");
        assertThat(slackPublisher).isNotNull();

        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + slackPublisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo(
                "Deleting a default notification publisher is forbidden.");
    }

    @Test
    void getNotificationPublisherConfigShouldReturnJsonSchema() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final NotificationPublisher slackPublisher = qm.getNotificationPublisher("Slack");

        final Response response = jersey.target(
                        "%s/%s/configSchema".formatted(V1_NOTIFICATION_PUBLISHER, slackPublisher.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "$schema": "https://json-schema.org/draft/2020-12/schema"
                        }
                        """);
    }

    @Test
    void shouldDispatchTestWorkflowRunPerGroupTargetingOnlyTheRequestedRule() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        NotificationPublisher slackPublisher = qm.getNotificationPublisher("Slack");
        slackPublisher.setName(slackPublisher.getName() + " Test Rule");
        qm.persist(slackPublisher);
        qm.detach(NotificationPublisher.class, slackPublisher.getId());

        NotificationRule rule = qm.createNotificationRule(
                "Example Rule 1",
                NotificationScope.PORTFOLIO,
                NotificationLevel.INFORMATIONAL,
                slackPublisher);
        qm.createNotificationRule(
                        "Other Rule",
                        NotificationScope.PORTFOLIO,
                        NotificationLevel.INFORMATIONAL,
                        slackPublisher)
                .setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));

        final Set<NotificationGroup> groups = Set.of(
                NotificationGroup.BOM_CONSUMED,
                NotificationGroup.BOM_PROCESSED,
                NotificationGroup.BOM_PROCESSING_FAILED,
                NotificationGroup.BOM_VALIDATION_FAILED,
                NotificationGroup.NEW_VULNERABILITY,
                NotificationGroup.NEW_VULNERABLE_DEPENDENCY,
                NotificationGroup.POLICY_VIOLATION,
                NotificationGroup.PROJECT_CREATED,
                NotificationGroup.PROJECT_AUDIT_CHANGE,
                NotificationGroup.VEX_CONSUMED,
                NotificationGroup.VEX_PROCESSED);
        rule.setNotifyOn(groups);
        rule.setPublisherConfig("{\"destination\":\"https://example.com/webhook\"}");

        final Response response = jersey
                .target(V1_NOTIFICATION_PUBLISHER + "/test/" + rule.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("", MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        assertThat(response.getStatus()).isEqualTo(200);

        final Collection<? extends CreateWorkflowRunRequest<?>> requests = captureBatchedCreateRunRequests();
        assertThat(requests).hasSize(groups.size());
        assertThat(requests).allSatisfy(request -> {
            assertThat(request.workflowInstanceId())
                    .startsWith("publish-test-notification:" + rule.getUuid() + ":");
            final var arg = (PublishNotificationWorkflowArg) request.argument();
            assertThat(arg.getNotificationRuleNamesList()).containsExactly("Example Rule 1");
            assertThat(arg.getNotification().getTitle()).startsWith("[TEST] ");
        });
        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldDispatchTestNotificationForScheduledSummaryRule() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        new DefaultNotificationPublisherInitializer().seedDefaultPublishers(pluginManager);

        final NotificationPublisher slackPublisher = qm.getNotificationPublisher("Slack");
        final NotificationRule rule = qm.createScheduledNotificationRule("Scheduled Rule",
                NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, slackPublisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
        rule.setPublisherConfig("{\"destination\":\"https://example.com/webhook\"}");

        final Response response = jersey
                .target(V1_NOTIFICATION_PUBLISHER + "/test/" + rule.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("", MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        assertThat(response.getStatus()).isEqualTo(200);

        final Collection<? extends CreateWorkflowRunRequest<?>> requests = captureBatchedCreateRunRequests();
        assertThat(requests).singleElement().satisfies(request -> {
            assertThat(request.workflowInstanceId())
                    .isEqualTo("publish-test-notification:%s:NEW_VULNERABILITIES_SUMMARY".formatted(rule.getUuid()));
            final var arg = (PublishNotificationWorkflowArg) request.argument();
            assertThat(arg.getNotificationRuleNamesList()).containsExactly("Scheduled Rule");
            assertThat(arg.getNotification().getTitle()).startsWith("[TEST] ");
        });
    }

    @Test
    void shouldReturnNotFoundWhenRuleDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        final Response response = jersey
                .target(V1_NOTIFICATION_PUBLISHER + "/test/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(404);
        verify(DEX_ENGINE_MOCK, never()).createRuns(any());
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Collection<? extends CreateWorkflowRunRequest<?>> captureBatchedCreateRunRequests() {
        final ArgumentCaptor<Collection> captor = ArgumentCaptor.forClass(Collection.class);
        verify(DEX_ENGINE_MOCK).createRuns(captor.capture());
        return (Collection<? extends CreateWorkflowRunRequest<?>>) captor.getValue();
    }

}
