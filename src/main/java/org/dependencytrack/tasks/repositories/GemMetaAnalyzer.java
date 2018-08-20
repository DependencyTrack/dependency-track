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
package org.dependencytrack.tasks.repositories;

import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import com.github.packageurl.PackageURL;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import io.github.openunirest.http.exceptions.UnirestException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.util.HttpClientFactory;

/**
 * An IMetaAnalyzer implementation that supports Ruby Gems.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class GemMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(GemMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://rubygems.org";
    private static final String API_URL = "/api/v1/versions/%s/latest.json";

    GemMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.GEM.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.GEM;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(Component component) {
        Unirest.setHttpClient(HttpClientFactory.createClient());
        MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            final String url = String.format(baseUrl + API_URL, component.getPurl().getName());
            try {
                HttpResponse<JsonNode> response = Unirest.get(url)
                        .header("accept", "application/json")
                        .asJson();
                if (response.getStatus() == 200) {
                    if (response.getBody() != null && response.getBody().getObject() != null) {
                        String latest = response.getBody().getObject().getString("version");
                        meta.setLatestVersion(latest);
                    }
                } else {
                    LOGGER.debug("HTTP Status : " + response.getStatus() + " " + response.getStatusText());
                    LOGGER.debug(" - RepositoryType URL : " + url);
                    LOGGER.debug(" - Package URL : " + component.getPurl().canonicalize());
                    Notification.dispatch(new Notification()
                            .scope(NotificationScope.SYSTEM)
                            .group(NotificationGroup.REPOSITORY)
                            .title(NotificationConstants.Title.REPO_ERROR)
                            .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. URL: " + url + " HTTP Status: " + response.getStatus() + ". Check log for details." )
                            .level(NotificationLevel.ERROR)
                    );
                }
            } catch (UnirestException e) {
                LOGGER.error("Request failure", e);
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.REPOSITORY)
                        .title(NotificationConstants.Title.REPO_ERROR)
                        .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. Check log for details. " + e.getMessage())
                        .level(NotificationLevel.ERROR)
                );
            }
        }
        return meta;
    }

}
