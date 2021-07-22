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
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import org.dependencytrack.util.DateUtil;

/**
 * An IMetaAnalyzer implementation that supports Cargo via crates.io compatible repos
 *
 * @author Steve Springett
 * @since 4.1.0
 */
public class CargoMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(CargoMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://crates.io";
    private static final String API_URL = "/api/v1/crates/%s";

    CargoMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.CARGO.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.CARGO;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            final String url = String.format(baseUrl + API_URL, component.getPurl().getName());
            try {
                final HttpResponse<JsonNode> response = ui.get(url)
                        .header("accept", "application/json")
                        .asJson();
                if (response.getStatus() == 200) {
                    if (response.getBody() != null && response.getBody().getObject() != null) {
                        final JSONObject crate = response.getBody().getObject().optJSONObject("crate");
                        if (crate != null) {
                            final String latest = crate.getString("newest_version");
                            meta.setLatestVersion(latest);
                        }
                        final JSONArray versions = response.getBody().getObject().optJSONArray("versions");
                        if (versions != null) {
                            for (int i=0; i<versions.length(); i++) {
                                final JSONObject version =  versions.getJSONObject(i);
                                final String versionString = version.optString("num");
                                if (meta.getLatestVersion() != null && meta.getLatestVersion().equals(versionString)) {
                                    final String publishedTimestamp = version.optString("created_at");
                                    try {
                                        meta.setPublishedTimestamp(DateUtil.fromISO8601(publishedTimestamp));
                                    } catch (IllegalArgumentException  e) {
                                        LOGGER.warn("An error occurred while parsing published time", e);
                                    }
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
