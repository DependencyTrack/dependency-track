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
package org.owasp.dependencytrack.tasks.scanners;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.util.JavaVersion;
import alpine.util.SystemUtil;
import com.github.packageurl.PackageURL;
import io.github.openunirest.http.HttpResponse;
import io.github.openunirest.http.JsonNode;
import io.github.openunirest.http.Unirest;
import io.github.openunirest.http.exceptions.UnirestException;
import org.json.JSONObject;
import org.owasp.dependencytrack.event.MetricsUpdateEvent;
import org.owasp.dependencytrack.event.NspAnalysisEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.nsp.NspCheckParser;
import org.owasp.dependencytrack.parser.nsp.model.Advisory;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.util.HttpClientFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using Node Security Platform.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NspAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final String NSP_API_BASE_URL = "https://api.nodesecurity.io/check";
    private static final Logger LOGGER = Logger.getLogger(NspAnalysisTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof NspAnalysisEvent) {
            final NspAnalysisEvent event = (NspAnalysisEvent)e;
            LOGGER.info("Starting NSP analysis task");

            //todo: remove this check when Java 9 is eventually a requirement
            JavaVersion javaVersion = SystemUtil.getJavaVersion();
            if (javaVersion.getMajor() == 8 && javaVersion.getUpdate() < 101) {
                LOGGER.error("Unable to perform analysis via Node Security Platform. NSP requires Java 1.8.0_101 or higher.");
            } else {
                if (event.getComponents().size() > 0) {
                    analyze(event.getComponents());
                } else {
                    super.analyze();
                }
            }
            LOGGER.info("NSP analysis complete");
        }
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(List<Component> components) {
        final List<Component> nspCandidates = new ArrayList<>();
        final JSONObject npmDependencies = new JSONObject();
        for (Component component : components) {

            PackageURL purl = component.getPurl();
            if (super.shouldAnalyze(purl)) {
                nspCandidates.add(component);
                npmDependencies.put(purl.getName(), purl.getVersion());
            }

        }

        // Build a minimal package.json in memory
        JSONObject packageJson = new JSONObject();
        packageJson.put("name", "test-package");
        packageJson.put("version", "1.0.0");
        packageJson.put("dependencies", npmDependencies);

        // Wrap the package.json content in a value called package for use with NSP
        JSONObject wrapper = new JSONObject();
        wrapper.put("package", packageJson);

        try {
            // Submit the wrapped package.json to NSP for analysis and process results
            List<Advisory> advisories = submit(wrapper);
            processResults(nspCandidates, advisories);
        } catch (UnirestException e) {
            LOGGER.error("An error occurred while analyzing", e);
        }
        LOGGER.info("Analyzing " + nspCandidates.size() + " component(s)");
    }

    /**
     * Submits the payload to the NSP service
     */
    private List<Advisory> submit(JSONObject payload) throws UnirestException {
        Unirest.setHttpClient(HttpClientFactory.createClient());
        final HttpResponse<JsonNode> jsonResponse = Unirest.post(NSP_API_BASE_URL)
                .header("Content-Type", "application/json")
                .header("X-NSP-VERSION", "3.2.1")
                .body(payload)
                .asJson();
        if (jsonResponse.getStatus() == 200) {
            final NspCheckParser parser = new NspCheckParser();
            return parser.parse(jsonResponse.getBody());
        } else {
            LOGGER.warn("Received unexpected HTTP response " + jsonResponse.getStatus() + " " + jsonResponse.getStatusText());
        }
        return null;
    }

    /**
     * Processes NSP results.
     */
    private void processResults(List<Component> components, List<Advisory> advisories) {
        LOGGER.info("Processing NSP advisories");
        try (QueryManager qm = new QueryManager()) {
            for (Advisory advisory: advisories) {
                Component component = getComponentFromAdvisory(components, advisory);
                Vulnerability vulnerabiity = qm.getVulnerabilityByVulnId(Vulnerability.Source.NSP, String.valueOf(advisory.getId()));
                if (component != null && vulnerabiity != null) {
                    qm.addVulnerability(vulnerabiity, component);
                }
                Event.dispatch(new MetricsUpdateEvent(component));
            }
        }
    }

    /**
     * Resolves a Component from the metadata in the advisory.
     */
    private Component getComponentFromAdvisory(List<Component> components, Advisory advisory) {
        for (Component component: components) {
            PackageURL purl = component.getPurl();
            if (purl != null) {
                if (purl.getName().equalsIgnoreCase(advisory.getModuleName())
                        && purl.getVersion().equalsIgnoreCase(advisory.getVersion())) {
                    return component;
                }
            }
        }
        return null;
    }

}
