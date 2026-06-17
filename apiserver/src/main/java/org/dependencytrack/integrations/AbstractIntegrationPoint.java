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
package org.dependencytrack.integrations;

import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.persistence.QueryManager;
import org.slf4j.Logger;

import static org.dependencytrack.notification.api.NotificationFactory.createIntegrationErrorNotification;

public abstract class AbstractIntegrationPoint implements IntegrationPoint {

    protected QueryManager qm;

    public void setQueryManager(final QueryManager qm) {
        this.qm = qm;
    }

    public void handleUnexpectedHttpResponse(final Logger logger, final String url, final int statusCode, final String statusText) {
        logger.error("An error occurred while communicating with the " + name() + " integration point");
        logger.error("HTTP Status : " + statusCode + " " + statusText);
        logger.error("Request URL : " + url);

        new JdoNotificationEmitter(qm).emit(
                createIntegrationErrorNotification("""
                        An error occurred while communicating with the %s integration point. \
                        URL: %s - HTTP Status: %s. Check log for details.""".formatted(name(), url, statusCode)));
    }

    public void handleException(final Logger logger, final Exception e) {
        logger.error("An error occurred with the " + name() + " integration point", e);

        new JdoNotificationEmitter(qm).emit(
                createIntegrationErrorNotification("""
                        An error occurred with the %s integration point. \
                        Check log for details. %s""".formatted(name(), e)));
    }
}
