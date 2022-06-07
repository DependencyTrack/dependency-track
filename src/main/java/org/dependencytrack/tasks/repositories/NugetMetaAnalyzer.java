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

import alpine.common.logging.Logger;
import com.github.packageurl.PackageURL;
import kong.unirest.GetRequest;
import kong.unirest.HttpRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.maven.artifact.versioning.ComparableVersion;
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

    public static final DateFormat[] SUPPORTED_DATE_FORMATS = new DateFormat[]{
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX"),
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    };
    private static final Logger LOGGER = Logger.getLogger(NugetMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://api.nuget.org";

    private static final String INDEX_URL = "/v3/index.json";

    private static final String DEFAULT_VERSION_QUERY_ENDPOINT = "/v3-flatcontainer/%s/index.json";

    private static final String DEFAULT_REGISTRATION_ENDPOINT = "/v3/registration5-semver1/%s/%s.json";

    private String versionQueryUrl;

    private String registrationUrl;

    NugetMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;

        // Set defaults that work with NuGet.org just in case the index endpoint is not available
        this.versionQueryUrl = baseUrl + DEFAULT_VERSION_QUERY_ENDPOINT;
        this.registrationUrl = baseUrl + DEFAULT_REGISTRATION_ENDPOINT;
    }

    @Override
    public void setRepositoryBaseUrl(String baseUrl) {
        super.setRepositoryBaseUrl(baseUrl);

        initializeEndpoints();
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
        final String url = String.format(versionQueryUrl, component.getPurl().getName().toLowerCase());
        try {
            final HttpResponse<JsonNode> response = httpGet(url);
            if (response.getStatus() == 200) {
                if (response.getBody() != null && response.getBody().getObject() != null) {
                    final JSONArray versions = response.getBody().getObject().getJSONArray("versions");
                    final String latest = findLatestVersion(versions); // get the last version in the array
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

    private String findLatestVersion(JSONArray versions) {
        if (versions.length() < 1) {
            return null;
        }

        ComparableVersion latestVersion = new ComparableVersion(versions.getString(0));

        for (int i = 1; i < versions.length(); i++) {
            ComparableVersion version = new ComparableVersion(versions.getString(i));
            if (version.compareTo(latestVersion) > 0) {
                latestVersion = version;
            }
        }

        return latestVersion.toString();
    }

    private HttpResponse<JsonNode> httpGet(String url) {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HttpRequest<GetRequest> request = ui.get(url).header("accept", "application/json");

        if (username != null || password != null) {
            request.basicAuth(username, password);
        }

        return request.asJson();
    }

    private boolean performLastPublishedCheck(final MetaModel meta, final Component component) {
        final String url = String.format(registrationUrl, component.getPurl().getName().toLowerCase(), meta.getLatestVersion());
        try {
            final HttpResponse<JsonNode> response = httpGet(url);
            if (response.getStatus() == 200) {
                if (response.getBody() != null && response.getBody().getObject() != null) {
                    final String updateTime = response.getBody().getObject().optString("published", null);
                    if (updateTime != null) {
                        meta.setPublishedTimestamp(parseUpdateTime(updateTime));
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

    private void initializeEndpoints() {
        final String url = baseUrl + INDEX_URL;
        try {
            final HttpResponse<JsonNode> response = httpGet(url);
            if (response.getStatus() == 200 && response.getBody() != null && response.getBody().getObject() != null) {
                final JSONArray resources = response.getBody().getObject().getJSONArray("resources");
                final JSONObject packageBaseResource = findResourceByType(resources, "PackageBaseAddress");
                final JSONObject registrationsBaseResource = findResourceByType(resources, "RegistrationsBaseUrl");
                if (packageBaseResource != null && registrationsBaseResource != null) {
                    versionQueryUrl = packageBaseResource.getString("@id") + "%s/index.json";
                    registrationUrl = registrationsBaseResource.getString("@id") + "%s/%s.json";
                }
            }
        } catch (UnirestException e) {
            handleRequestException(LOGGER, e);
        }
    }

    private JSONObject findResourceByType(JSONArray resources, String type) {
        for (int i = 0; i < resources.length(); i++) {
            String resourceType = resources.getJSONObject(i).getString("@type");
            if (resourceType != null && resourceType.toLowerCase().startsWith(type.toLowerCase())) {
                return resources.getJSONObject(i);
            }
        }

        return null;
    }

    private Date parseUpdateTime(String updateTime) {
        if (updateTime == null) {
            return null;
        }

        // NuGet repositories may use differing date formats, so we try a few date formats that are commonly used until the right one is found.
        for (DateFormat dateFormat : SUPPORTED_DATE_FORMATS) {
            try {
                return dateFormat.parse(updateTime);
            } catch (ParseException e) {
                LOGGER.warn("An error occurred while parsing upload time for a NuGet component - Repo returned: " + updateTime);
            }
        }

        return null;
    }
}
