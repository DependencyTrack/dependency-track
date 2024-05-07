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
package org.dependencytrack.tasks;

import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import javax.json.Json;
import javax.json.JsonObject;

import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;

import alpine.common.logging.Logger;
import alpine.security.crypto.DataEncryption;
import alpine.server.mail.SendMail;
import alpine.server.mail.SendMailException;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;

import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_FROM_ADDR;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_PASSWORD;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SERVER_HOSTNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SERVER_PORT;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SSLTLS;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_TRUSTCERT;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_USERNAME;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_KEY;
import static org.dependencytrack.notification.publisher.Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY;

public class SendScheduledNotificationTask implements Runnable {
    private ScheduledNotificationRule scheduledNotificationRule;
    private ScheduledExecutorService service;
    private static final Logger LOGGER = Logger.getLogger(SendScheduledNotificationTask.class);

    public SendScheduledNotificationTask(ScheduledNotificationRule scheduledNotificationRule, ScheduledExecutorService service) {
        this.scheduledNotificationRule = scheduledNotificationRule;
        this.service = service;
    }

    @Override
    public void run() {
        String content = "";
        final String mimeType;
        final boolean smtpEnabled;
        final String smtpFrom;
        final String smtpHostname;
        final int smtpPort;
        final String smtpUser;
        final String encryptedSmtpPassword;
        final boolean smtpSslTls;
        final boolean smtpTrustCert;
        Map<Project, List<Vulnerability>> newProjectVulnerabilities;
        Map<Project, List<PolicyViolation>> newProjectPolicyViolations;

        try (QueryManager qm = new QueryManager()) {
            scheduledNotificationRule = qm.getObjectByUuid(ScheduledNotificationRule.class, scheduledNotificationRule.getUuid());
            if (scheduledNotificationRule == null) {
                LOGGER.info("shutdown ExecutorService for Scheduled notification " + scheduledNotificationRule.getUuid());
                service.shutdown();
            } else {
                // if (scheduledNotificationRule.getLastExecutionTime().equals(scheduledNotificationRule.getCreated())) {
                //     LOGGER.info("schedulednotification just created. No Information to show");
                // } else {
                final List<Long> projectIds = scheduledNotificationRule.getProjects().stream().map(proj -> proj.getId()).toList();
                newProjectVulnerabilities = qm.getNewVulnerabilitiesForProjectsSince(scheduledNotificationRule.getLastExecutionTime(), projectIds);
                newProjectPolicyViolations = qm.getNewPolicyViolationsForProjectsSince(scheduledNotificationRule.getLastExecutionTime(), projectIds);

                NotificationPublisher notificationPublisher = qm.getNotificationPublisher("Email");

                JsonObject notificationPublisherConfig = Json.createObjectBuilder()
                        .add(CONFIG_TEMPLATE_MIME_TYPE_KEY, notificationPublisher.getTemplateMimeType())
                        .add(CONFIG_TEMPLATE_KEY, notificationPublisher.getTemplate())
                        .build();

                PebbleEngine pebbleEngine = new PebbleEngine.Builder().build();
                String literalTemplate = notificationPublisherConfig.getString(CONFIG_TEMPLATE_KEY);
                final PebbleTemplate template = pebbleEngine.getLiteralTemplate(literalTemplate);
                mimeType = notificationPublisherConfig.getString(CONFIG_TEMPLATE_MIME_TYPE_KEY);

                final Map<String, Object> context = new HashMap<>();
                context.put("length", newProjectVulnerabilities.size());
                context.put("vulnerabilities", newProjectVulnerabilities);
                context.put("policyviolations", newProjectPolicyViolations);
                final Writer writer = new StringWriter();
                template.evaluate(writer, context);
                content = writer.toString();

                smtpEnabled = qm.isEnabled(EMAIL_SMTP_ENABLED);
                if (!smtpEnabled) {
                    System.out.println("SMTP is not enabled; Skipping notification ");
                    return;
                }
                smtpFrom = qm.getConfigProperty(EMAIL_SMTP_FROM_ADDR.getGroupName(),EMAIL_SMTP_FROM_ADDR.getPropertyName()).getPropertyValue();
                smtpHostname = qm.getConfigProperty(EMAIL_SMTP_SERVER_HOSTNAME.getGroupName(),EMAIL_SMTP_SERVER_HOSTNAME.getPropertyName()).getPropertyValue();
                smtpPort = Integer.parseInt(qm.getConfigProperty(EMAIL_SMTP_SERVER_PORT.getGroupName(),EMAIL_SMTP_SERVER_PORT.getPropertyName()).getPropertyValue());
                smtpUser = qm.getConfigProperty(EMAIL_SMTP_USERNAME.getGroupName(),EMAIL_SMTP_USERNAME.getPropertyName()).getPropertyValue();
                encryptedSmtpPassword = qm.getConfigProperty(EMAIL_SMTP_PASSWORD.getGroupName(),EMAIL_SMTP_PASSWORD.getPropertyName()).getPropertyValue();
                smtpSslTls = qm.isEnabled(EMAIL_SMTP_SSLTLS);
                smtpTrustCert = qm.isEnabled(EMAIL_SMTP_TRUSTCERT);
                final boolean smtpAuth = (smtpUser != null && encryptedSmtpPassword != null);
                final String decryptedSmtpPassword;
                try {
                    decryptedSmtpPassword = (encryptedSmtpPassword != null) ? DataEncryption.decryptAsString(encryptedSmtpPassword) : null;
                } catch (Exception e) {
                    System.out.println("Failed to decrypt SMTP password");
                    return;
                }
                // String[] destinations = scheduledNotificationRule.getDestinations().split(" ");
                try {
                    final SendMail sendMail = new SendMail()
                            .from(smtpFrom)
                            // .to(destinations)
                            .subject("[Dependency-Track] " + "ScheduledNotification")
                            .body(content)
                            .bodyMimeType(mimeType)
                            .host(smtpHostname)
                            .port(smtpPort)
                            .username(smtpUser)
                            .password(decryptedSmtpPassword)
                            .smtpauth(smtpAuth)
                            .useStartTLS(smtpSslTls)
                            .trustCert(smtpTrustCert);
                    sendMail.send();
                } catch (SendMailException | RuntimeException e) {
                    LOGGER.debug("Failed to send notification email ");
                    LOGGER.debug(e.getMessage());
                }
                // }
                // qm.updateScheduledNotificationInfoNextExecution(scheduledNotificationRule);
            }

        } catch (Exception e) {
            LOGGER.debug(e.getMessage());
        }

    }

}
