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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.util.ComponentVersion;
import org.json.JSONArray;
import org.json.JSONObject;
import com.github.packageurl.PackageURL;
import alpine.common.logging.Logger;

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
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {

            final String packageName = getPackageName(component.getPurl());

            final String url = String.format(baseUrl + API_URL, packageName);
            try (final CloseableHttpResponse response = processHttpRequest(url)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    if (response.getEntity()!=null) {
                        String responseString = EntityUtils.toString(response.getEntity());
                        var jsonObject = new JSONObject(responseString);
                        var releasesArray = jsonObject.getJSONArray("releases");
                        analyzeReleases(meta, releasesArray);
                    }
                } else {
                    handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), component);
                }
            } catch (IOException e) {
                handleRequestException(LOGGER, e);
            }
        }
        return meta;
    }

    private String getPackageName(final PackageURL pUrl) {
        if (pUrl.getNamespace() != null) {
            return pUrl.getNamespace().replace("@", "%40") + "%2F" + pUrl.getName();
        } else {
            return pUrl.getName();
        }
    }

    private void analyzeReleases(final MetaModel meta, final JSONArray releasesArray) {
        // get list of versions and published timestamps
        Map<String, String> versions = new HashMap<>();
        for (int i = 0; i<releasesArray.length(); i++) {
            JSONObject release = releasesArray.getJSONObject(i);
            final String version = release.optString("version", null);
            final String insertedAt = release.optString("inserted_at", null);
            versions.put(version, insertedAt);
        }
        final String highestVersion = ComponentVersion.findHighestVersion(new ArrayList<>(versions.keySet()));
        meta.setLatestVersion(highestVersion);

        final String insertedAt = versions.get(highestVersion);
        meta.setPublishedTimestamp(getPublishedTimestamp(insertedAt));
    }

    private Date getPublishedTimestamp(final String insertedAt) {
        final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        Date publishedTimestamp = null;
        try {
            publishedTimestamp = dateFormat.parse(insertedAt);
        } catch (ParseException e) {
            LOGGER.warn("An error occurred while parsing published time", e);
        }
        return publishedTimestamp;
    }

}
