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
import kong.unirest.json.JSONObject;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * An IMetaAnalyzer implementation that supports Hex.
 *
 * @author Steve Springett
 * @since 3.7.0
 */
public class HexMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(HexMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://hex.pm";
    private static final String API_URL = "/api/packages/%s";

    HexMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.HEX.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.HEX;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {

            final String packageName;
            if (component.getPurl().getNamespace() != null) {
                packageName = component.getPurl().getNamespace().replace("@", "%40") + "%2F" + component.getPurl().getName();
            } else {
                packageName = component.getPurl().getName();
            }

            final String url = String.format(baseUrl + API_URL, packageName);
            try {
                final HttpResponse<JsonNode> response = ui.get(url)
                        .header("accept", "application/json")
                        .asJson();
                if (response.getStatus() == 200) {
                    if (response.getBody() != null && response.getBody().getObject() != null) {
                        final JSONArray releasesArray = response.getBody().getObject().getJSONArray("releases");
                        if (releasesArray.length() > 0) {
                            // The first one in the array is always the latest version
                            final JSONObject release = releasesArray.getJSONObject(0);
                            final String latest = release.optString("version", null);
                            meta.setLatestVersion(latest);
                            final String insertedAt = release.optString("inserted_at", null);
                            if (insertedAt != null) {
                                final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
                                try {
                                    final Date published = dateFormat.parse(insertedAt);
                                    meta.setPublishedTimestamp(published);
                                } catch (ParseException e) {
                                    LOGGER.warn("An error occurred while parsing published time", e);
                                }
                            }
                        }
                    }
                } else {
                    handleUnexpectedHttpResponse(LOGGER, url, response.getStatus(), response.getStatusText(), component);
                }
            } catch (UnirestException e) {
                handleRequestException(LOGGER, e);
            }
        }
        return meta;
    }

}
