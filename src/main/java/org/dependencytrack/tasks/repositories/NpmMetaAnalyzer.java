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
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;

/**
 * An IMetaAnalyzer implementation that supports NPM.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class NpmMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(NpmMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://registry.npmjs.org";
    private static final String API_URL = "/-/package/%s/dist-tags";

    NpmMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.NPM.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.NPM;
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
                        final String latest = response.getBody().getObject().optString("latest");
                        if (latest != null) {
                            meta.setLatestVersion(latest);
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
