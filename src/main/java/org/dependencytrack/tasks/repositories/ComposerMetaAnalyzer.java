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
package org.dependencytrack.tasks.repositories;

import alpine.common.logging.Logger;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.apache.maven.artifact.versioning.ComparableVersion;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;

/**
 * An IMetaAnalyzer implementation that supports Composer.
 */
public class ComposerMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(ComposerMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://repo.packagist.org";
    private static final String API_URL_V1 = "/p/%s/%s.json";
    private static final String API_URL_V2 = "/p2/%s/%s.json";

    ComposerMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    @Override
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.COMPOSER.equals(component.getPurl().getType());
    }

    @Override
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.COMPOSER;
    }

    @Override
    public MetaModel analyze(final Component component) {
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() == null) {
            return meta;
        }

        final String urlV2 = String.format(baseUrl + API_URL_V2, urlEncode(component.getPurl().getNamespace()), urlEncode(component.getPurl().getName()));
        final String urlV1 = String.format(baseUrl + API_URL_V1, urlEncode(component.getPurl().getNamespace()), urlEncode(component.getPurl().getName()));

        try {
            if (processRepository(urlV2, meta)) {
                return meta;
            }
            if (processRepository(urlV1, meta)) {
                return meta;
            }
            LOGGER.warn("Failed to retrieve package metadata from both Composer V1 and V2 endpoints.");
        } catch (IOException ex) {
            handleRequestException(LOGGER, ex);
        } catch (Exception ex) {
            LOGGER.error("Unexpected error during analysis", ex);
            throw new MetaAnalyzerException(ex);
        }
        return meta;
    }

    private boolean processRepository(String url, MetaModel meta) throws IOException {
        try (final CloseableHttpResponse response = processHttpRequest(url)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK && response.getEntity() != null) {
                String jsonString = EntityUtils.toString(response.getEntity());
                JSONObject jsonObject = new JSONObject(jsonString);

                if (jsonObject.has("packages")) {
                    parseComposerData(jsonObject.getJSONObject("packages"), meta);
                    return true;
                } else {
                    LOGGER.warn("Unexpected JSON structure from: " + url);
                }
            } else {
                LOGGER.warn("HTTP response status not OK for URL: " + url);
            }
        } catch (JSONException e) {
            LOGGER.error("Invalid JSON response from: " + url, e);
        }
        return false;
    }

    private void parseComposerData(JSONObject packages, MetaModel meta) {
        for (String packageName : packages.keySet()) {
            Object packageData = packages.get(packageName);
            if (packageData instanceof JSONObject) {
                // For Composer 1 (/p endpoint)
                JSONObject packageDataObj = (JSONObject) packageData;
                JSONObject versionsObj = packageDataObj.optJSONObject("versions");
                if (versionsObj != null) {
                    parseVersions(versionsObj, meta);
                }
            } else if (packageData instanceof JSONArray) {
                // For Composer 2 (/p2 endpoint)
                JSONArray versionsArray = (JSONArray) packageData;
                for (int i = 0; i < versionsArray.length(); i++) {
                    JSONObject versionData = versionsArray.getJSONObject(i);
                    parseVersionData(versionData, meta);
                }
            } else {
                LOGGER.warn("Unexpected package data type for package: " + packageName);
            }
        }
    }

    private void parseVersions(JSONObject versions, MetaModel meta) {
        if (versions == null) {
            return;
        }

        for (String versionKey : versions.keySet()) {
            JSONObject versionData = versions.optJSONObject(versionKey);
            if (versionData != null) {
                parseVersionData(versionData, meta);
            }
        }
    }

    private void parseVersionData(JSONObject versionData, MetaModel meta) {
        String version = versionData.optString("version", null);
        String normalizedVersion = normalizeVersion(versionData.optString("version_normalized", version));
        String time = versionData.optString("time", null);

        if (version == null || normalizedVersion == null) {
            LOGGER.warn("Version data missing required keys: " + versionData);
            return;
        }

        String currentLatestVersionNormalized = meta.getLatestVersion() != null
                ? normalizeVersion(meta.getLatestVersion())
                : null;

        try {
            ComparableVersion newVersion = new ComparableVersion(normalizedVersion);
            ComparableVersion currentLatestVersion = currentLatestVersionNormalized != null
                    ? new ComparableVersion(currentLatestVersionNormalized)
                    : null;

            if (currentLatestVersion == null || newVersion.compareTo(currentLatestVersion) > 0) {
                meta.setLatestVersion(version);
                if (time != null) {
                    try {
                        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
                        meta.setPublishedTimestamp(format.parse(time));
                    } catch (ParseException e) {
                        LOGGER.error("Failed to parse timestamp: " + time, e);
                    }
                }
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Invalid version format: " + normalizedVersion, e);
        }
    }

    private static String normalizeVersion(String version) {
        if (version == null) {
            return null;
        }
        version = version.trim();

        // Remove leading 'v' or 'V'
        if (version.startsWith("v") || version.startsWith("V")) {
            version = version.substring(1);
        }

        // Remove trailing ".0" components
        version = version.replaceAll("(\\.0)+$", "");

        return version;
    }
}
