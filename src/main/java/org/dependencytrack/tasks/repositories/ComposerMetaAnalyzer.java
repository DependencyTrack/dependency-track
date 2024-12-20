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
import org.dependencytrack.exception.MetaAnalyzerException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;

/**
 * An IMetaAnalyzer implementation that supports Composer.
 *
 * @author Szabolcs (Szasza) Palmer
 * @since 4.1.0
 */
public class ComposerMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(ComposerMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://repo.packagist.org";

    /**
     * @see <a href="https://packagist.org/apidoc#get-package-data">Packagist's API doc for "Getting package data - Using the Composer v2 metadata"</a>
     * Example: https://repo.packagist.org/p2/monolog/monolog.json
     */
    private static final String PACKAGE_META_DATA_URL = "/p2/%s/%s.json";

    ComposerMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.COMPOSER.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.COMPOSER;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() == null) {
            return meta;
        }

        final String url = String.format(baseUrl + PACKAGE_META_DATA_URL, urlEncode(component.getPurl().getNamespace()), urlEncode(component.getPurl().getName()));
        try (final CloseableHttpResponse response = processHttpRequest(url)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), component);
                return meta;
            }
            if (response.getEntity().getContent() == null) {
                return meta;
            }
            String jsonString = EntityUtils.toString(response.getEntity());
            if (jsonString.equalsIgnoreCase("")) {
                return meta;
            }
            if (jsonString.equalsIgnoreCase("{}")) {
                return meta;
            }
            JSONObject jsonObject = new JSONObject(jsonString);
            final String expectedResponsePackage = component.getPurl().getNamespace() + "/" + component.getPurl().getName();
            final JSONObject responsePackages = jsonObject
                    .getJSONObject("packages");
            if (!responsePackages.has(expectedResponsePackage)) {
                // the package no longer exists - for v2 there's no example (yet), v1 example https://repo.packagist.org/p/magento/adobe-ims.json
                return meta;
            }
            final JSONArray composerPackageVersions = responsePackages.getJSONArray(expectedResponsePackage);

            final ComparableVersion latestVersion = new ComparableVersion(stripLeadingV(component.getPurl().getVersion()));
            final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

            composerPackageVersions.forEach(item -> {
                JSONObject composerPackage = (JSONObject) item;
                String version =  composerPackage.getString("version");
                if (version.startsWith("dev-") || version.endsWith("-dev")) {
                    // dev versions are excluded, since they are not pinned but a VCS-branch.
                    // this case doesn't seem to happen anymore with V2, as dev (untagged) releases are not part of the response anymore
                    return;
                }

                final String version_normalized = composerPackage.getString("version_normalized");
                ComparableVersion currentComparableVersion = new ComparableVersion(version_normalized);
                if (currentComparableVersion.compareTo(latestVersion) < 0) {
                    // smaller version can be skipped
                    return;
                }

                latestVersion.parseVersion(stripLeadingV(version_normalized));
                meta.setLatestVersion(version);

                final String published = composerPackage.getString("time");
                try {
                    meta.setPublishedTimestamp(dateFormat.parse(published));
                } catch (ParseException e) {
                    LOGGER.warn("An error occurred while parsing upload time", e);
                }
            });
        } catch (IOException ex) {
            handleRequestException(LOGGER, ex);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
        }

        return meta;
    }

    private static String stripLeadingV(String s) {
        return s.startsWith("v") || s.startsWith("V")
                ? s.substring(1)
                : s;
    }
}
