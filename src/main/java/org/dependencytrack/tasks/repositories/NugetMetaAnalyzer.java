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
import com.github.packageurl.PackageURL;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import kong.unirest.json.JSONArray;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * An IMetaAnalyzer implementation that supports Nuget.
 *
 * @author Steve Springett
 * @since 3.4.0
 */
public class NugetMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(NugetMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://api.nuget.org";
    private static final String VERSION_QUERY_URL = "/v3-flatcontainer/%s/index.json";
    private static final String REGISTRATION_URL = "/v3/registration3/%s/%s.json";

    NugetMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.NUGET.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.NUGET;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            if (performVersionCheck(meta, component)) {
                performLastPublishedCheck(meta, component);
            }
        }
        return meta;
    }

    private boolean performVersionCheck(final MetaModel meta, final Component component) {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final String url = String.format(baseUrl + VERSION_QUERY_URL, component.getPurl().getName().toLowerCase());
        try {
            final HttpResponse<JsonNode> response = ui.get(url)
                    .header("accept", "application/json")
                    .asJson();
            if (response.getStatus() == 200) {
                if (response.getBody() != null && response.getBody().getObject() != null) {
                    final JSONArray versions = response.getBody().getObject().getJSONArray("versions");
                    final String latest = versions.getString(versions.length()-1); // get the last version in the array
                    meta.setLatestVersion(latest);
                }
                return true;
            } else {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatus(), response.getStatusText(), component);
            }
        } catch (UnirestException e) {
            handleRequestException(LOGGER, e);
        }
        return false;
    }

    private boolean performLastPublishedCheck(final MetaModel meta, final Component component) {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final String url = String.format(baseUrl + REGISTRATION_URL, component.getPurl().getName().toLowerCase(), meta.getLatestVersion());
        try {
            final HttpResponse<JsonNode> response = ui.get(url)
                    .header("accept", "application/json")
                    .asJson();
            if (response.getStatus() == 200) {
                if (response.getBody() != null && response.getBody().getObject() != null) {
                    final String updateTime = response.getBody().getObject().optString("published", null);
                    if (updateTime != null) {
                        final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
                        try {
                            final Date published = dateFormat.parse(updateTime);
                            meta.setPublishedTimestamp(published);
                        } catch (ParseException e) {
                            LOGGER.warn("An error occurred while parsing upload time for " + component.getPurl().toString() + " - Repo returned: " + updateTime);
                        }
                    }
                }
                return true;
            } else {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatus(), response.getStatusText(), component);
            }
        } catch (UnirestException e) {
            handleRequestException(LOGGER, e);
        }
        return false;
    }
}
