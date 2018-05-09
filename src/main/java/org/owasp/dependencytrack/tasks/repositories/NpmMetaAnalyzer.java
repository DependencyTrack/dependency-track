/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.tasks.repositories;

import alpine.logging.Logger;
import com.github.packageurl.PackageURL;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.util.HttpClientFactory;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An IMetaAnalyzer implementation that supports NPM.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class NpmMetaAnalyzer implements IMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(NpmMetaAnalyzer.class);
    private static final String API_URL = "https://registry.npmjs.org/-/package/%s/dist-tags";

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.NPM.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public List<MetaModel> analyze(List<Component> components) {
        return components.stream().map(this::analyze).collect(Collectors.toList());
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(Component component) {
        Unirest.setHttpClient(HttpClientFactory.createClient());
        MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            final String url = String.format(API_URL, component.getPurl().getName());
            try {
                HttpResponse<JsonNode> response = Unirest.get(url)
                        .header("accept", "application/json")
                        .asJson();
                if (response.getStatus() == 200) {
                    if (response.getBody() != null && response.getBody().getObject() != null) {
                        String latest = response.getBody().getObject().getString("latest");
                        meta.setLatestVersion(latest);
                    }
                } else {
                    LOGGER.debug("HTTP Status : " + response.getStatus() + " " + response.getStatusText());
                    LOGGER.debug(" - Repository URL : " + url);
                    LOGGER.debug(" - Package URL : " + component.getPurl().canonicalize());
                }
            } catch (UnirestException e) {
                LOGGER.error("Request failure", e);
            }
        }
        return meta;
    }

}
