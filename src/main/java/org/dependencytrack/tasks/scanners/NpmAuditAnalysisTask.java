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
package org.dependencytrack.tasks.scanners;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import com.github.packageurl.PackageURL;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.event.NpmAuditAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.npm.NpmAuditParser;
import org.dependencytrack.parser.npm.model.Advisory;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.json.JSONObject;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Subscriber task that performs an analysis of component using NPM Audit API.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NpmAuditAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final String API_BASE_URL = "https://registry.npmjs.org/-/npm/v1/security/audits";
    private static final Logger LOGGER = Logger.getLogger(NpmAuditAnalysisTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NpmAuditAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_NPMAUDIT_ENABLED)) {
                return;
            }
            final NpmAuditAnalysisEvent event = (NpmAuditAnalysisEvent)e;
            LOGGER.info("Starting Node Audit analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            } else {
                super.analyze();
            }
            LOGGER.info("Node Audit analysis complete");
        }
    }

    /**
     * Determines if the {@link NpmAuditAnalysisTask} is suitable for analysis based on the PackageURL.
     *
     * @param purl the PackageURL to analyze
     * @return true if NpmAuditAnalysisTask should analyze, false if not
     */
    public boolean shouldAnalyze(final PackageURL purl) {
        if (purl == null) {
            return false;
        }
        return "npm".equals(purl.getType()) && !isCacheCurrent(Vulnerability.Source.NPM, API_BASE_URL, purl.toString());
    }

    /**
     * Analyzes a list of Components. The NPM Audit API is only capable of analyzing one
     * version of a node module at a time. For example, attempting to analyze three versions
     * of 'serve' for example will result in only the last version in the payload specified
     * being scanned. Therefore, this method uses a Map with the name of the module being the
     * maps key to ensure multiple versions are not sent at the same time. This will result
     * in multiple requests being made to the NPM Audit API.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        final ArrayList<Component> backlog = new ArrayList<>(components);
        while (!backlog.isEmpty()) {
            // Defines a Map of Components to analyze
            final Map<String, Component> npmCandidates = new HashMap<>();

            // NPM payload objects
            final JSONObject npmRequires = new JSONObject();
            final JSONObject npmDependencies = new JSONObject();

            for (Iterator<Component> iterator = backlog.iterator(); iterator.hasNext();) {
                Component component = iterator.next();
                final PackageURL purl = component.getPurl();
                if (shouldAnalyze(purl)) {
                    if (!npmCandidates.containsKey(component.getName())) {
                        npmCandidates.put(component.getName(), component);
                        npmRequires.put(purl.getName(), purl.getVersion());
                        npmDependencies.put(purl.getName(), new JSONObject().put("version", purl.getVersion()));
                        iterator.remove(); // Remove the current component being iterated on
                    }
                } else {
                    iterator.remove(); // Remove the current component being iterated on
                }
            }

            if (npmRequires.length() > 0) {
                // Build a minimal package-lock.json in memory
                final JSONObject packageJson = new JSONObject();
                packageJson.put("name", "test-package");
                packageJson.put("version", "1.0.0");
                packageJson.put("requires", npmRequires);
                packageJson.put("dependencies", npmDependencies);

                try {
                    // Submit the package-lock.json to Node Audit API for analysis and process results
                    final List<Advisory> advisories = submit(packageJson);
                    processResults(new ArrayList<>(npmCandidates.values()), advisories);
                } catch (UnirestException e) {
                    LOGGER.error("An error occurred while analyzing", e);
                }
                LOGGER.info("Analyzing " + npmCandidates.size() + " component(s)");
            }
        }
    }

    /**
     * Submits the payload to the NPM service
     */
    private List<Advisory> submit(final JSONObject payload) throws UnirestException {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HttpResponse<JsonNode> jsonResponse = ui.post(API_BASE_URL)
                .header("user-agent", "npm/6.1.0 node/v10.5.0 linux x64")
                .header("npm-in-ci", "false")
                .header("npm-scope", "")
                .header("npm-session", generateRandomSession())
                .header("content-type", "application/json")
                .body(payload)
                .asJson();
        if (jsonResponse.getStatus() == 200) {
            final NpmAuditParser parser = new NpmAuditParser();
            return parser.parse(jsonResponse.getBody());
        } else {
            LOGGER.warn("Received unexpected HTTP response " + jsonResponse.getStatus() + " " + jsonResponse.getStatusText());
        }
        return new ArrayList<>();
    }

    /**
     * Processes NPM results.
     */
    private void processResults(final List<Component> components, final List<Advisory> advisories) {
        LOGGER.info("Processing NPM advisories");
        try (QueryManager qm = new QueryManager()) {
            for (final Advisory advisory: advisories) {
                final Component component = getComponentFromAdvisory(components, advisory);
                final Vulnerability vulnerabiity = qm.getVulnerabilityByVulnId(Vulnerability.Source.NPM, String.valueOf(advisory.getId()));
                if (component != null && vulnerabiity != null) {
                    NotificationUtil.analyzeNotificationCriteria(vulnerabiity, component);
                    qm.addVulnerability(vulnerabiity, component);
                }
                Event.dispatch(new MetricsUpdateEvent(component));
            }
            for (final Component component: components) {
                updateAnalysisCacheStats(qm, Vulnerability.Source.NPM, API_BASE_URL, component.getPurl().toString());
            }
        }
    }

    /**
     * Resolves a Component from the metadata in the advisory.
     */
    private Component getComponentFromAdvisory(final List<Component> components, final Advisory advisory) {
        for (final Component component: components) {
            final PackageURL purl = component.getPurl();
            if (purl != null) {
                if (purl.getName().equalsIgnoreCase(advisory.getModuleName())
                        && purl.getVersion().equalsIgnoreCase(advisory.getVersion())) {
                    return component;
                }
            }
        }
        return null;
    }

    /**
     * Generates a random 16 character lower-case hex string.
     */
    private String generateRandomSession() {
        final int length = 16;
        final SecureRandom r = new SecureRandom();
        final StringBuilder sb = new StringBuilder();
        while(sb.length() < length){
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, length);
    }

}
