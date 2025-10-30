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
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class NixpkgsMetaAnalyzer extends AbstractMetaAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(NixpkgsMetaAnalyzer.class);
    private static final String DEFAULT_CHANNEL_URL = "https://channels.nixos.org/nixpkgs-unstable/packages.json.br";
    private static final Cache<String, Map<String, String>> CACHE = Caffeine.newBuilder()
            .expireAfterWrite(60, TimeUnit.MINUTES)
            .maximumSize(1)
            .build();

    NixpkgsMetaAnalyzer() {
        this.baseUrl = DEFAULT_CHANNEL_URL;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(Component component) {
        Map<String, String> latestVersions = CACHE.get("nixpkgs", cacheKey -> {
            final var versions = new HashMap<String, String>();
            try (final CloseableHttpClient client = HttpClients.createDefault()) {
                try (final CloseableHttpResponse packagesResponse = processHttpRequest5(client)) {
                    if (packagesResponse != null && packagesResponse.getCode() == HttpStatus.SC_OK) {
                        var reader = new BufferedReader(new InputStreamReader(packagesResponse.getEntity().getContent()));
                        var packages = new JSONObject(new JSONTokener(reader)).getJSONObject("packages").toMap().values();
                        packages.forEach(pkg -> {
                            // FUTUREWORK(mangoiv): there are potentially packages with the same pname
                            if (pkg instanceof HashMap jsonPkg) {
                                final var pname = jsonPkg.get("pname");
                                final var version = jsonPkg.get("version");
                                versions.putIfAbsent((String) pname, (String) version);
                            }
                        });


                    }
                }
            } catch (IOException ex) {
                LOGGER.debug(ex.toString());
                handleRequestException(LOGGER, ex);
            } catch (Exception ex) {
                LOGGER.debug(ex.toString());
                throw new MetaAnalyzerException(ex);
            }
            return versions;
        });
        final var meta = new MetaModel(component);
        final var purl = component.getPurl();
        if (purl != null) {
            final var newerVersion = latestVersions.get(purl.getName());
            if (newerVersion != null) {
                meta.setLatestVersion(newerVersion);
            }
        }
        return meta;
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
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.NIXPKGS;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        final var purl = component.getPurl();
        return purl != null && "nixpkgs".equals(purl.getType());
    }
}
