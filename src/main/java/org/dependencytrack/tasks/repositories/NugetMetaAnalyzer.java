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
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
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
        try (final CloseableHttpResponse response = processHttpRequest(url)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                if (response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    var jsonObject = new JSONObject(responseString);
                    final JSONArray versions = jsonObject.getJSONArray("versions");
                    final String latest = findLatestVersion(versions); // get the last version in the array
                    meta.setLatestVersion(latest);
                }
                return true;
            } else {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), component);
            }
        } catch (IOException e) {
            handleRequestException(LOGGER, e);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
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

    private boolean performLastPublishedCheck(final MetaModel meta, final Component component) {
        final String url = String.format(registrationUrl, component.getPurl().getName().toLowerCase(), meta.getLatestVersion());
        try (final CloseableHttpResponse response = processHttpRequest(url)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                if (response.getEntity() != null) {
                    String stringResponse = EntityUtils.toString(response.getEntity());
                    if (!stringResponse.equalsIgnoreCase("") && !stringResponse.equalsIgnoreCase("{}")) {
                        JSONObject jsonResponse = new JSONObject(stringResponse);
                        final String updateTime = jsonResponse.optString("published", null);
                        if (updateTime != null) {
                            meta.setPublishedTimestamp(parseUpdateTime(updateTime));
                        }
                        return true;
                    }
                }
            } else {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), component);
            }
        } catch (IOException e) {
            handleRequestException(LOGGER, e);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
        }
        return false;
    }

    private void initializeEndpoints() {
        final String url = baseUrl + INDEX_URL;
        try {
            try (final CloseableHttpResponse response = processHttpRequest(url)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    if(response.getEntity()!=null){
                    String responseString = EntityUtils.toString(response.getEntity());
                        JSONObject responseJson = new JSONObject(responseString);
                        final JSONArray resources = responseJson.getJSONArray("resources");
                        final JSONObject packageBaseResource = findResourceByType(resources, "PackageBaseAddress");
                        final JSONObject registrationsBaseResource = findResourceByType(resources, "RegistrationsBaseUrl");
                        if (packageBaseResource != null && registrationsBaseResource != null) {
                            versionQueryUrl = packageBaseResource.getString("@id") + "%s/index.json";
                            registrationUrl = registrationsBaseResource.getString("@id") + "%s/%s.json";
                        }
                    }
                }
            }
        } catch (IOException e) {
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
