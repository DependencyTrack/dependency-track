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
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;

public class NixpkgsMetaAnalyzer extends AbstractMetaAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(NixpkgsMetaAnalyzer.class);
    private static final String DEFAULT_CHANNEL_URL = "https://channels.nixos.org/nixpkgs-unstable/packages.json.br";
    private static NixpkgsMetaAnalyzer nixpkgsMetaAnalyzer = new NixpkgsMetaAnalyzer();
    // this doesn't really make sense wrt the "AbstractMetaAnalyzer"
    // because this statically known url will just redirect us to
    // the actual URL
    private final HashMap<String, String> latestVersion;

    private NixpkgsMetaAnalyzer() {
        this.baseUrl = DEFAULT_CHANNEL_URL;
        HashMap<String, String> newLatestVersion = new HashMap<>();

        try (final CloseableHttpClient client = HttpClients.createDefault()) {
            try (final CloseableHttpResponse packagesResponse = processHttpRequest5(client)) {
                if (packagesResponse != null && packagesResponse.getCode() == HttpStatus.SC_OK) {
                    final var entity = packagesResponse.getEntity();
                    if (entity != null) {
                        // TODO(mangoiv): is this the fastest way we can do this?
                        final var entityString = EntityUtils.toString(entity);
                        final var packages = new JSONObject(entityString).getJSONObject("packages").toMap().values();
                        packages.forEach(pkg -> {
                            // FUTUREWORK(mangoiv): there are potentially packages with the same pname
                            if (pkg instanceof HashMap jsonPkg) {
                                final var pname = jsonPkg.get("pname");
                                final var version = jsonPkg.get("version");
                                newLatestVersion.putIfAbsent((String) pname, (String) version);
                            }
                        });
                    }

                }
            }
        } catch (IOException ex) {
            LOGGER.debug(ex.toString());
            handleRequestException(LOGGER, ex);
        } catch (Exception ex) {
            LOGGER.debug(ex.toString());
            throw new MetaAnalyzerException(ex);
        }
        this.latestVersion = newLatestVersion;
        LOGGER.info("finished updating the nixpkgs meta analyzer");
    }

    public static NixpkgsMetaAnalyzer getNixpkgsMetaAnalyzer() {
        return nixpkgsMetaAnalyzer;
    }

    private CloseableHttpResponse processHttpRequest5(CloseableHttpClient client) throws IOException {
        try {
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            final HttpGet request = new HttpGet(uriBuilder.build().toString());
            request.addHeader("accept", "application/json");

            return client.execute(request);

        } catch (URISyntaxException ex) {
            handleRequestException(LOGGER, ex);
            return null;
        }
    }

    /**
     * updates the NixpkgsMetaAnalyzer asynchronously by fetching a new version
     * of the standard channel
     */
    public void updateNixpkgsMetaAnalyzer() {
        new Thread(() -> nixpkgsMetaAnalyzer = new NixpkgsMetaAnalyzer()).start();
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.NIXPKGS;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        // FUTUREWORK(mangoiv): add nixpkgs to https://github.com/package-url/packageurl-java/blob/master/src/main/java/com/github/packageurl/PackageURL.java
        final var purl = component.getPurl();
        return purl != null && "nixpkgs".equals(purl.getType());
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(Component component) {
        final var meta = new MetaModel(component);
        final var purl = component.getPurl();
        if (purl != null) {
            final var newerVersion = latestVersion.get(purl.getName());
            if (newerVersion != null) {
                meta.setLatestVersion(newerVersion);
            }
        }
        return meta;
    }
}
