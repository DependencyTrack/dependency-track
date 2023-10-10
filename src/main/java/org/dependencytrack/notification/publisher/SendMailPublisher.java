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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.notification.publisher;

import alpine.common.logging.Logger;
import alpine.common.util.BooleanUtil;
import alpine.model.ConfigProperty;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.notification.Notification;
import alpine.security.crypto.DataEncryption;
import alpine.server.mail.SendMail;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.persistence.QueryManager;

import javax.json.JsonObject;
import javax.json.JsonString;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

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
    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().newLineTrimming(false).build();

    public void inform(final Notification notification, final JsonObject config) {
        if (config == null) {
            LOGGER.warn("No configuration found. Skipping notification.");
            return;
        }
        final String[] destinations = parseDestination(config);
        sendNotification(notification, config, destinations);
    }

    public void inform(final Notification notification, final JsonObject config, List<Team> teams) {
        if (config == null) {
            LOGGER.warn("No configuration found. Skipping notification.");
            return;
        }
        final String[] destinations = parseDestination(config, teams);
        sendNotification(notification, config, destinations);
    }

    private void sendNotification(Notification notification, JsonObject config, String[] destinations) {
        PebbleTemplate template = getTemplate(config);
        String mimeType = getTemplateMimeType(config);
        final String content = prepareTemplate(notification, template);
        if (destinations == null || content == null) {
            LOGGER.warn("A destination or template was not found. Skipping notification");
            return;
        }
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty smtpEnabled = qm.getConfigProperty(EMAIL_SMTP_ENABLED.getGroupName(), EMAIL_SMTP_ENABLED.getPropertyName());
            final ConfigProperty smtpFrom = qm.getConfigProperty(EMAIL_SMTP_FROM_ADDR.getGroupName(), EMAIL_SMTP_FROM_ADDR.getPropertyName());
            final ConfigProperty smtpHostname = qm.getConfigProperty(EMAIL_SMTP_SERVER_HOSTNAME.getGroupName(), EMAIL_SMTP_SERVER_HOSTNAME.getPropertyName());
            final ConfigProperty smtpPort = qm.getConfigProperty(EMAIL_SMTP_SERVER_PORT.getGroupName(), EMAIL_SMTP_SERVER_PORT.getPropertyName());
            final ConfigProperty smtpUser = qm.getConfigProperty(EMAIL_SMTP_USERNAME.getGroupName(), EMAIL_SMTP_USERNAME.getPropertyName());
            final ConfigProperty smtpPass = qm.getConfigProperty(EMAIL_SMTP_PASSWORD.getGroupName(), EMAIL_SMTP_PASSWORD.getPropertyName());
            final ConfigProperty smtpSslTls = qm.getConfigProperty(EMAIL_SMTP_SSLTLS.getGroupName(), EMAIL_SMTP_SSLTLS.getPropertyName());
            final ConfigProperty smtpTrustCert = qm.getConfigProperty(EMAIL_SMTP_TRUSTCERT.getGroupName(), EMAIL_SMTP_TRUSTCERT.getPropertyName());

            if (!BooleanUtil.valueOf(smtpEnabled.getPropertyValue())) {
                LOGGER.warn("SMTP is not enabled");
                return; // smtp is not enabled
            }
            final boolean smtpAuth = (smtpUser.getPropertyValue() != null && smtpPass.getPropertyValue() != null);
            final String password = (smtpPass.getPropertyValue() != null) ? DataEncryption.decryptAsString(smtpPass.getPropertyValue()) : null;
            final SendMail sendMail = new SendMail()
                    .from(smtpFrom.getPropertyValue())
                    .to(destinations)
                    .subject("[Dependency-Track] " + notification.getTitle())
                    .body(content)
                    .bodyMimeType(mimeType)
                    .host(smtpHostname.getPropertyValue())
                    .port(Integer.valueOf(smtpPort.getPropertyValue()))
                    .username(smtpUser.getPropertyValue())
                    .password(password)
                    .smtpauth(smtpAuth)
                    .useStartTLS(BooleanUtil.valueOf(smtpSslTls.getPropertyValue()))
                    .trustCert(Boolean.valueOf(smtpTrustCert.getPropertyValue()));
            sendMail.send();
        } catch (Exception e) {
            LOGGER.error("An error occurred sending output email notification", e);
        }
  }

    @Override
    public PebbleEngine getTemplateEngine() {
        return ENGINE;
    }

    static String[] parseDestination(final JsonObject config) {
        JsonString destinationString = config.getJsonString("destination");
        if ((destinationString == null) || destinationString.getString().isEmpty()) {
          return null;
        }
        return destinationString.getString().split(",");
    }

    static String[] parseDestination(final JsonObject config, final List<Team> teams) {
        String[] destination = teams.stream().flatMap(
                team -> Stream.of(
                                Optional.ofNullable(config.getJsonString("destination"))
                                        .map(JsonString::getString)
                                        .stream()
                                        .flatMap(dest -> Arrays.stream(dest.split(",")))
                                        .filter(Predicate.not(String::isEmpty)),
                                Optional.ofNullable(team.getManagedUsers()).orElseGet(Collections::emptyList).stream().map(ManagedUser::getEmail).filter(Objects::nonNull),
                                Optional.ofNullable(team.getLdapUsers()).orElseGet(Collections::emptyList).stream().map(LdapUser::getEmail).filter(Objects::nonNull),
                                Optional.ofNullable(team.getOidcUsers()).orElseGet(Collections::emptyList).stream().map(OidcUser::getEmail).filter(Objects::nonNull)
                        )
                        .reduce(Stream::concat)
                        .orElseGet(Stream::empty)
                )
                .distinct()
                .toArray(String[]::new);
        return destination.length == 0 ? null : destination;
    }
}
