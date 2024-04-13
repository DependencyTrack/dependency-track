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
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONObject;

import java.io.IOException;

public class HackageMetaAnalyzer extends AbstractMetaAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(HackageMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://hackage.haskell.org/";

    HackageMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.HACKAGE;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        final var purl = component.getPurl();
        return purl != null && "hackage".equals(purl.getType());
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final var meta = new MetaModel(component);
        final var purl = component.getPurl();
        if (purl != null) {
            final var url = baseUrl + "/package/" + purl.getName() + "/preferred";
            try (final CloseableHttpResponse response = processHttpRequest(url)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    final var entity = response.getEntity();
                    if (entity != null) {
                        String responseString = EntityUtils.toString(entity);
                        final var deserialized = new JSONObject(responseString);
                        final var preferred = deserialized.getJSONArray("normal-version");
                        // the latest version is the first in the list
                        if (preferred != null) {
                            final var latest = preferred.getString(0);
                            meta.setLatestVersion(latest);
                        }
                        // the hackage API doesn't expose the "published_at" information
                        // we could use https://flora.pm/experimental/packages/{namespace}/{packageName}
                        // but it appears this isn't reliable yet
                    }
                } else {
                    var statusLine = response.getStatusLine();
                    handleUnexpectedHttpResponse(LOGGER, url, statusLine.getStatusCode(), statusLine.getReasonPhrase(), component);
                }
            } catch (IOException ex) {
                handleRequestException(LOGGER, ex);
            } catch (Exception ex) {
                throw new MetaAnalyzerException(ex);
            }
        }
        return meta;
    }
}
