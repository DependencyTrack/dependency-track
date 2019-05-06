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
package org.dependencytrack.tasks.repositories;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

/**
 * Base abstract class that all IMetaAnalyzer implementations should likely extend.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public abstract class AbstractMetaAnalyzer implements IMetaAnalyzer {

    String baseUrl;

    /**
     * {@inheritDoc}
     */
    public void setRepositoryBaseUrl(String baseUrl) {
        baseUrl = StringUtils.trimToNull(baseUrl);
        if (baseUrl == null) {
            return;
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        this.baseUrl = baseUrl;
    }

    public void handleUnexpectedHttpResponse(final Logger logger, String url, final int statusCode, final String statusText, final Component component) {
        logger.debug("HTTP Status : " + statusCode + " " + statusText);
        logger.debug(" - RepositoryType URL : " + url);
        logger.debug(" - Package URL : " + component.getPurl().canonicalize());
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.REPOSITORY)
                .title(NotificationConstants.Title.REPO_ERROR)
                .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. URL: " + url + " HTTP Status: " + statusCode + ". Check log for details." )
                .level(NotificationLevel.ERROR)
        );
    }

    public void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.REPOSITORY)
                .title(NotificationConstants.Title.REPO_ERROR)
                .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }

}
