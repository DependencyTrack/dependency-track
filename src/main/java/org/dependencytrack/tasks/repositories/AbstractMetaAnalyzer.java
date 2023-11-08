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

import java.io.IOException;
import java.net.URISyntaxException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.model.Component;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.util.HttpUtil;
import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;

/**
 * Base abstract class that all IMetaAnalyzer implementations should likely extend.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public abstract class AbstractMetaAnalyzer implements IMetaAnalyzer {

    protected String baseUrl;

    protected String username;

    protected String password;

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

    public void setRepositoryUsernameAndPassword(String username, String password) {
        this.username = StringUtils.trimToNull(username);
        this.password = StringUtils.trimToNull(password);
    }

    protected void handleUnexpectedHttpResponse(final Logger logger, String url, final int statusCode, final String statusText, final Component component) {
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

    protected void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.REPOSITORY)
                .title(NotificationConstants.Title.REPO_ERROR)
                .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }

    protected CloseableHttpResponse processHttpRequest(String url) throws IOException {
        final Logger logger = Logger.getLogger(getClass());
        try {
            URIBuilder uriBuilder = new URIBuilder(url);
            final HttpUriRequest request = new HttpGet(uriBuilder.build().toString());
            request.addHeader("accept", "application/json");
            if (username != null || password != null) {
                request.addHeader("Authorization", HttpUtil.basicAuthHeaderValue(username, password));
            }
            return HttpClientPool.getClient().execute(request);
        }catch (URISyntaxException ex){
            handleRequestException(logger, ex);
            return null;
        }
    }

    /**
     * Parse two version strings and return the one containing the highest version
     *
     * @param v1string first version to compare
     * @param v2string second version to compare
     * @return the highest of two versions as string value
     */
    public static String highestVersion(String v1string, String v2string) {
        if (v1string == null) {
            return v2string;
        } else if (v2string == null) {
            return v1string;
        } else {
            ComparableVersion v1 = new ComparableVersion(stripLeadingV(v1string));
            ComparableVersion v2 = new ComparableVersion(stripLeadingV(v2string));
            return v1.compareTo(v2) > 0 ? v1string : v2string;
        }
    }

    protected static String stripLeadingV(String s) {
        return s.startsWith("v")
                ? s.substring(1)
                : s;
    }

}
