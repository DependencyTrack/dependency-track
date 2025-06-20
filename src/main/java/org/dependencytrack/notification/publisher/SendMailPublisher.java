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
package org.dependencytrack.notification.publisher;

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.server.mail.SendMail;
import alpine.server.mail.SendMailException;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.extension.core.DisallowExtensionCustomizerBuilder;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.apache.commons.text.StringEscapeUtils;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DebugDataEncryption;

import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_PREFIX;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_FROM_ADDR;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_PASSWORD;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SERVER_HOSTNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SERVER_PORT;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SSLTLS;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_TRUSTCERT;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_USERNAME;

public class SendMailPublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(SendMailPublisher.class);
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder()
            .registerExtensionCustomizer(new DisallowExtensionCustomizerBuilder()
                    .disallowedTokenParserTags(List.of("include"))
                    .build())
            .newLineTrimming(false)
            .build();

    @Override
    public void inform(final PublishContext ctx, final Notification notification, final JsonObject config) {
        if (config == null) {
            LOGGER.warn("No configuration found; Skipping notification (%s)".formatted(ctx));
            return;
        }
        final String[] destinations = getDestinations(config, ctx.ruleId());
        sendNotification(ctx, notification, config, destinations);
    }

    private void sendNotification(final PublishContext ctx, Notification notification, JsonObject config, String[] destinations) {
        if (config == null) {
            LOGGER.warn("No publisher configuration found; Skipping notification (%s)".formatted(ctx));
            return;
        }
        if (destinations == null) {
            LOGGER.warn("No destination(s) provided; Skipping notification (%s)".formatted(ctx));
            return;
        }

        final String content;
        final String mimeType;
        try {
            final PebbleTemplate template = getTemplate(config);
            mimeType = getTemplateMimeType(config);
            content = prepareTemplate(notification, template);
        } catch (IOException | RuntimeException e) {
            LOGGER.error("Failed to prepare notification content (%s)".formatted(ctx), e);
            return;
        }

        final boolean smtpEnabled;
        final String smtpFrom;
        final String smtpHostname;
        final int smtpPort;
        final String smtpUser;
        final String encryptedSmtpPassword;
        final boolean smtpSslTls;
        final boolean smtpTrustCert;
        String emailSubjectPrefix;

        try (QueryManager qm = new QueryManager()) {
            smtpEnabled = qm.isEnabled(EMAIL_SMTP_ENABLED);
            if (!smtpEnabled) {
                LOGGER.warn("SMTP is not enabled; Skipping notification (%s)".formatted(ctx));
                return;
            }

            smtpFrom = qm.getConfigProperty(EMAIL_SMTP_FROM_ADDR.getGroupName(), EMAIL_SMTP_FROM_ADDR.getPropertyName()).getPropertyValue();
            emailSubjectPrefix = qm.getConfigProperty(EMAIL_PREFIX.getGroupName(), EMAIL_PREFIX.getPropertyName()).getPropertyValue();
            emailSubjectPrefix = emailSubjectPrefix == null ? " " : emailSubjectPrefix;
            smtpHostname = qm.getConfigProperty(EMAIL_SMTP_SERVER_HOSTNAME.getGroupName(), EMAIL_SMTP_SERVER_HOSTNAME.getPropertyName()).getPropertyValue();
            smtpPort = Integer.parseInt(qm.getConfigProperty(EMAIL_SMTP_SERVER_PORT.getGroupName(), EMAIL_SMTP_SERVER_PORT.getPropertyName()).getPropertyValue());
            smtpUser = qm.getConfigProperty(EMAIL_SMTP_USERNAME.getGroupName(), EMAIL_SMTP_USERNAME.getPropertyName()).getPropertyValue();
            encryptedSmtpPassword = qm.getConfigProperty(EMAIL_SMTP_PASSWORD.getGroupName(), EMAIL_SMTP_PASSWORD.getPropertyName()).getPropertyValue();
            smtpSslTls = qm.isEnabled(EMAIL_SMTP_SSLTLS);
            smtpTrustCert = qm.isEnabled(EMAIL_SMTP_TRUSTCERT);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to load SMTP configuration from datastore (%s)".formatted(ctx), e);
            return;
        }

        final boolean smtpAuth = (smtpUser != null && encryptedSmtpPassword != null);
        final String decryptedSmtpPassword;
        try {
            decryptedSmtpPassword = (encryptedSmtpPassword != null) ? DebugDataEncryption.decryptAsString(encryptedSmtpPassword) : null;
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt SMTP password (%s)".formatted(ctx), e);
            return;
        }
        String unescapedContent = StringEscapeUtils.unescapeHtml4(content);

        try {
            final SendMail sendMail = new SendMail()
                    .from(smtpFrom)
                    .to(destinations)
                    .subject(emailSubjectPrefix + " " + notification.getTitle())
                    .body(MediaType.TEXT_HTML.equals(mimeType) ? StringEscapeUtils.escapeHtml4(unescapedContent) : unescapedContent)
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
            LOGGER.error("Failed to send notification email via %s:%d (%s)"
                    .formatted(smtpHostname, smtpPort, ctx), e);
            return;
        }

        if (ctx.shouldLogSuccess()) {
            LOGGER.info("Notification email sent successfully via %s:%d (%s)"
                    .formatted(smtpHostname, smtpPort, ctx));
        }
  }

    @Override
    public PebbleEngine getTemplateEngine() {
        return ENGINE;
    }

    static String[] getDestinations(final JsonObject config, final long ruleId) {
        final var emails = new HashSet<String>();

        Optional.ofNullable(config.getJsonString("destination"))
                .map(JsonString::getString)
                .stream()
                .flatMap(dest -> Arrays.stream(dest.split(",")))
                .filter(Predicate.not(String::isEmpty))
                .forEach(emails::add);

        try (final var qm = new QueryManager()) {
            emails.addAll(qm.getTeamMemberEmailsForNotificationRule(ruleId));
        }

        return emails.isEmpty() ? null : emails.toArray(new String[0]);
    }
}
