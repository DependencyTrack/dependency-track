/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.notification.publisher;

import alpine.crypto.DataEncryption;
import alpine.logging.Logger;
import alpine.mail.SendMail;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.util.BooleanUtil;
import org.owasp.dependencytrack.persistence.QueryManager;

import javax.json.JsonObject;

import static org.owasp.dependencytrack.model.ConfigPropertyConstants.*;

public class SendMailPublisher implements Publisher {

    private static final Logger LOGGER = Logger.getLogger(SendMailPublisher.class);

    public void inform(Notification notification, JsonObject config) {
        try (QueryManager qm = new QueryManager()) {
            ConfigProperty smtpEnabled = qm.getConfigProperty(EMAIL_SMTP_ENABLED.getGroupName(), EMAIL_SMTP_ENABLED.getPropertyName());
            ConfigProperty smtpFrom = qm.getConfigProperty(EMAIL_SMTP_FROM_ADDR.getGroupName(), EMAIL_SMTP_FROM_ADDR.getPropertyName());
            ConfigProperty smtpHostname = qm.getConfigProperty(EMAIL_SMTP_SERVER_HOSTNAME.getGroupName(), EMAIL_SMTP_SERVER_HOSTNAME.getPropertyName());
            ConfigProperty smtpPort = qm.getConfigProperty(EMAIL_SMTP_SERVER_PORT.getGroupName(), EMAIL_SMTP_SERVER_PORT.getPropertyName());
            ConfigProperty smtpUser = qm.getConfigProperty(EMAIL_SMTP_USERNAME.getGroupName(), EMAIL_SMTP_USERNAME.getPropertyName());
            ConfigProperty smtpPass = qm.getConfigProperty(EMAIL_SMTP_PASSWORD.getGroupName(), EMAIL_SMTP_PASSWORD.getPropertyName());
            ConfigProperty smtpSslTls = qm.getConfigProperty(EMAIL_SMTP_SSLTLS.getGroupName(), EMAIL_SMTP_SSLTLS.getPropertyName());
            ConfigProperty smtpTrustCert = qm.getConfigProperty(EMAIL_SMTP_TRUSTCERT.getGroupName(), EMAIL_SMTP_TRUSTCERT.getPropertyName());

            if (!BooleanUtil.valueOf(smtpEnabled.getPropertyValue())) {
                return; // smtp is not enabled
            }
            final boolean smtpAuth = (smtpUser.getPropertyValue() != null && smtpPass.getPropertyValue() != null);
            final String destination = config.getString("destination");

            final String body =
                    "Timestamp: " + notification.getTimestamp().toString() + "\n" +
                            "Level:     " + notification.getLevel() + "\n" +
                            "Scope:     " + notification.getScope() + "\n" +
                            "Group:     " + notification.getGroup() + "\n" +
                            "Title:     " + notification.getTitle() + "\n\n" +
                            notification.getContent();

            final SendMail sendMail = new SendMail()
                    .from(smtpFrom.getPropertyValue())
                    .to(destination)
                    .subject("Dependency-Track Notification (" + notification.getLevel() + "): " + notification.getTitle())
                    .body(body)
                    .host(smtpHostname.getPropertyValue())
                    .port(Integer.valueOf(smtpPort.getPropertyValue()))
                    .username(smtpUser.getPropertyValue())
                    .password(DataEncryption.decryptAsString(smtpPass.getPropertyValue()))
                    .smtpauth(smtpAuth)
                    .useStartTLS(BooleanUtil.valueOf(smtpSslTls.getPropertyValue()))
                    .trustCert(Boolean.valueOf(smtpTrustCert.getPropertyValue()));
            sendMail.send();
        } catch (Exception e) {
            LOGGER.error("An error occurred sending output email notification", e);
        }
    }
}
