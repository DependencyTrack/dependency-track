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
import kong.unirest.json.JSONObject;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
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
    private static final String API_URL = "/p/%s/%s.json";

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
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() == null) {
            return meta;
        }

        final String url = String.format(baseUrl + API_URL, component.getPurl().getNamespace(), component.getPurl().getName());
        try {
            final HttpResponse<JsonNode> response = ui.get(url)
                    .header("accept", "application/json")
                    .asJson();
            if (response.getStatus() != 200) {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatus(), response.getStatusText(), component);
                return meta;
            }

            if (response.getBody() == null || response.getBody().getObject() == null) {
                return meta;
            }

            final JSONObject composerPackage = response
                    .getBody()
                    .getObject()
                    .getJSONObject("packages")
                    .getJSONObject(component.getPurl().getNamespace() + "/" + component.getPurl().getName());

            final ComparableVersion latestVersion = new ComparableVersion(stripLeadingV(component.getPurl().getVersion()));
            final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

            composerPackage.names().forEach(key_ -> {
                String key = (String) key_;
                if (key.startsWith("dev-") || key.endsWith("-dev")) {
                    // dev versions are excluded, since they are not pinned but a VCS-branch.
                    return;
                }

                final String version_normalized = composerPackage.getJSONObject(key).getString("version_normalized");
                ComparableVersion currentComparableVersion = new ComparableVersion(version_normalized);
                if ( currentComparableVersion.compareTo(latestVersion) < 0)
                {
                    // smaller version can be skipped
                    return;
                }

                final String version = composerPackage.getJSONObject(key).getString("version");
                latestVersion.parseVersion(stripLeadingV(version_normalized));
                meta.setLatestVersion(version);

                final String published = composerPackage.getJSONObject(key).getString("time");
                try {
                    meta.setPublishedTimestamp(dateFormat.parse(published));
                } catch (ParseException e) {
                    LOGGER.warn("An error occurred while parsing upload time", e);
                }
            });
        } catch (UnirestException e) {
            handleRequestException(LOGGER, e);
        }

        return meta;
    }

    private static String stripLeadingV(String s) {
        return s.startsWith("v")
                ? s.substring(1)
                : s;
    }
}
