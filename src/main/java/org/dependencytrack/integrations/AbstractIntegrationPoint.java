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
package org.dependencytrack.integrations;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;

public abstract class AbstractIntegrationPoint implements IntegrationPoint {

    protected QueryManager qm;

    public void setQueryManager(final QueryManager qm) {
        this.qm = qm;
    }

    public void handleUnexpectedHttpResponse(final Logger logger, final String url, final int statusCode, final String statusText) {
        logger.error("An error occurred while communicating with the " + name() + " integration point");
        logger.error("HTTP Status : " + statusCode + " " + statusText);
        logger.error("Request URL : " + url);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.INTEGRATION)
                .title(NotificationConstants.Title.INTEGRATION_ERROR)
                .content("An error occurred while communicating with the " + name()+ " integration point. URL: " + url + " - HTTP Status: " + statusCode + ". Check log for details." )
                .level(NotificationLevel.ERROR)
        );
    }

    public void handleException(final Logger logger, final Exception e) {
        logger.error("An error occurred with the " + name() + " integration point", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.INTEGRATION)
                .title(NotificationConstants.Title.INTEGRATION_ERROR)
                .content("An error occurred with the " + name() + " integration point. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }
}
