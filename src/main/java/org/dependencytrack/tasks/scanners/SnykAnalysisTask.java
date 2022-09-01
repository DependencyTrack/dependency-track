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

import alpine.common.logging.Logger;
import alpine.common.util.Pageable;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import kong.unirest.*;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.http.HttpHeaders;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.SnykAnalysisEvent;
import org.dependencytrack.model.*;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;

/**
 * Subscriber task that performs an analysis of component using Snyk vulnerability REST API.
 */
public class SnykAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final String API_BASE_URL = "https://api.snyk.io/rest/packages/";
    private static final String API_ENDPOINT = "/vulnerabilities?version=2022-04-04~experimental";
    private static final Logger LOGGER = Logger.getLogger(SnykAnalysisTask.class);
    private static final int PAGE_SIZE = 100;
    private String apiToken;

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.SNYK_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof SnykAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_SNYK_ENABLED)) {
                return;
            }
            try (QueryManager qm = new QueryManager()) {
                final ConfigProperty apiTokenProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN.getGroupName(),
                        ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN.getPropertyName()
                );
                if (apiTokenProperty == null || apiTokenProperty.getPropertyValue() == null) {
                    LOGGER.error("Please provide API token for use with Snyk");
                    return;
                }
                try {
                    apiToken = "token " + DataEncryption.decryptAsString(apiTokenProperty.getPropertyValue());
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the Snyk API Token. Skipping", ex);
                    return;
                }
            }
            final SnykAnalysisEvent event = (SnykAnalysisEvent) e;
            LOGGER.info("Starting Snyk vulnerability analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            }
            LOGGER.info("Snyk vulnerability analysis complete");
        }
    }

    /**
     * Determines if the {@link SnykAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if SnykAnalysisTask should analyze, false if not
     */
    public boolean isCapable(final Component component) {
        return component.getPurl() != null
                && component.getPurl().getScheme() != null
                && component.getPurl().getType() != null
                && component.getPurl().getName() != null
                && component.getPurl().getVersion() != null;
    }

    private String parsePurlToSnykUrlParam(PackageURL purl) {

        String url = purl.getScheme() + "%3A" + purl.getType() + "%2f";
        if (purl.getNamespace() != null) {
            url = url + purl.getNamespace() + "%2f";
        }
        url = url + purl.getName() + "%40" + purl.getVersion();
        return url;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        final Pageable<Component> paginatedComponents = new Pageable<>(PAGE_SIZE, components);
        while (!paginatedComponents.isPaginationComplete()) {
            final List<Component> paginatedList = paginatedComponents.getPaginatedList();
            for (final Component component: paginatedList) {
                try (QueryManager qm = new QueryManager()) {
                    final UnirestInstance ui = UnirestFactory.getUnirestInstance();
                    final String snykUrl = API_BASE_URL + parsePurlToSnykUrlParam(component.getPurl()) + API_ENDPOINT;
                    final GetRequest request = ui.get(snykUrl)
                            .header(HttpHeaders.AUTHORIZATION, apiToken);
                    final HttpResponse<JsonNode> jsonResponse = request.asJson();
                    if (jsonResponse.getStatus() == 200) {
                        handle(component, jsonResponse.getBody().getObject());
                    } else {
                        handleUnexpectedHttpResponse(LOGGER, API_BASE_URL, jsonResponse.getStatus(), jsonResponse.getStatusText());
                    }
                } catch (UnirestException e) {
                    handleRequestException(LOGGER, e);
                }
            }
            paginatedComponents.nextPage();
        }
    }

    private void handle(Component component, JSONObject object) {

        try (QueryManager qm = new QueryManager()) {

            final JSONObject data = object.optJSONObject("data");
            if (data != null) {
                final JSONObject attributes = data.optJSONObject("attributes");
                if (attributes != null) {

                    String purl = attributes.optString("purl", null);

                    final JSONArray vulnerabilities = attributes.optJSONArray("vulnerabilities");
                    if (vulnerabilities != null) {
                        for (int i = 0; i < vulnerabilities.length(); i++) {

                            final JSONObject snykVuln = vulnerabilities.getJSONObject(i);
                            if (snykVuln != null) {

                                Vulnerability vulnerability = new Vulnerability();
                                List<VulnerableSoftware> vsList = new ArrayList<>();
                                vulnerability.setSource(Vulnerability.Source.SNYK);
                                vulnerability.setVulnId(snykVuln.optString("id", null));

                                final JSONArray links = snykVuln.optJSONArray("links");
                                if (links != null) {
                                    final StringBuilder sb = new StringBuilder();
                                    for (int j = 0; j < links.length(); j++) {
                                        final JSONObject link = links.getJSONObject(j);
                                        String reference = link.optString("href", null);
                                        if (reference != null) {
                                            sb.append("* [").append(reference).append("](").append(reference).append(")\n");
                                        }
                                    }
                                    vulnerability.setReferences(sb.toString());
                                }

                                final JSONObject vulnAttributes = snykVuln.optJSONObject("attributes");
                                if (vulnAttributes != null) {
                                    vulnerability.setTitle(vulnAttributes.optString("title", null));
                                    vulnerability.setDescription(vulnAttributes.optString("description", null));
                                    vulnerability.setCreated(Date.from(jsonStringToTimestamp(vulnAttributes.optString("creation_time")).toInstant()));
                                    vulnerability.setPublished(Date.from(jsonStringToTimestamp(vulnAttributes.optString("publication_time")).toInstant()));
                                    vulnerability.setUpdated(Date.from(jsonStringToTimestamp(vulnAttributes.optString("modification_time")).toInstant()));

                                    final JSONArray cweIds = vulnAttributes.optJSONArray("cwe_ids");
                                    if (cweIds != null) {
                                        for (int j = 0; j < cweIds.length(); j++) {
                                            final Cwe cwe = CweResolver.getInstance().resolve(qm, cweIds.optString(j));
                                            if (cwe != null) {
                                                vulnerability.addCwe(cwe);
                                            }
                                        }
                                    }

                                    final JSONArray cvssArray = vulnAttributes.optJSONArray("cvss_details");
                                    if (cvssArray != null) {
                                        final JSONObject cvss = cvssArray.getJSONObject(0);
                                        if (cvss != null) {
                                            String severity = cvss.optString("severity", null);
                                            if (severity != null) {
                                                if (severity.equalsIgnoreCase("CRITICAL")) {
                                                    vulnerability.setSeverity(Severity.CRITICAL);
                                                } else if (severity.equalsIgnoreCase("HIGH")) {
                                                    vulnerability.setSeverity(Severity.HIGH);
                                                } else if (severity.equalsIgnoreCase("MEDIUM")) {
                                                    vulnerability.setSeverity(Severity.MEDIUM);
                                                } else if (severity.equalsIgnoreCase("LOW")) {
                                                    vulnerability.setSeverity(Severity.LOW);
                                                } else {
                                                    vulnerability.setSeverity(Severity.UNASSIGNED);
                                                }
                                            }
                                            vulnerability.setCvssV3Vector(cvss.optString("cvss_vector", null));
                                            final JSONObject cvssScore = cvss.optJSONObject("cvss_scores");
                                            if (cvssScore != null) {
                                                vulnerability.setCvssV3BaseScore(BigDecimal.valueOf(Double.valueOf(cvssScore.optString("base_score"))));
                                            }
                                        }
                                    }

                                    JSONArray ranges = vulnAttributes.optJSONArray("vulnerable_range");
                                    if (ranges != null) {
                                        vsList = parseVersionRanges(qm, purl, ranges);
                                    }
                                }
                                LOGGER.debug("Updating vulnerable software for Snyk vulnerability: " + vulnerability.getVulnId());
                                qm.persist(vsList);
                                Vulnerability synchronizedVulnerability = qm.synchronizeVulnerability(vulnerability, false);
                                synchronizedVulnerability.setVulnerableSoftware(new ArrayList<>(vsList));
                                qm.persist(synchronizedVulnerability);

                                final Component componentPersisted = qm.getObjectByUuid(Component.class, component.getUuid());
                                if (componentPersisted != null) {
                                    qm.addVulnerability(synchronizedVulnerability, componentPersisted, this.getAnalyzerIdentity());
                                    LOGGER.info("Snyk vulnerability added : " + synchronizedVulnerability.getVulnId() + " to component " + component.getName());
                                }
                            }
                            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                        }
                    }
                }
            }
        }
    }

    public List<VulnerableSoftware> parseVersionRanges(final QueryManager qm, final String purl, final JSONArray ranges) {

        List<VulnerableSoftware> vulnerableSoftwares = new ArrayList<>();
        if (purl == null) {
            LOGGER.debug("No PURL provided - skipping");
            return null;
        }

        final PackageURL packageURL;
        try {
            packageURL = new PackageURL(purl);
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Invalid PURL  " + purl + " - skipping", ex);
            return null;
        }

        for (int i = 0; i < ranges.length(); i++) {

            String range = ranges.optString(i);
            String versionStartIncluding = null;
            String versionStartExcluding = null;
            String versionEndIncluding = null;
            String versionEndExcluding = null;

            final String[] parts = Arrays.stream(range.split(",")).map(String::trim).toArray(String[]::new);
            for (String part : parts) {
                if (part.startsWith(">=") || part.startsWith("[")) {
                    versionStartIncluding = part.replace(">=", "").replace("[", "").trim();
                } else if (part.startsWith(">") || part.startsWith("(")) {
                    versionStartExcluding = part.replace(">", "").replace("(", "").trim();
                } else if (part.startsWith("<=") || part.endsWith("]")) {
                    versionEndIncluding = part.replace("<=", "").replace("]", "").trim();
                } else if (part.startsWith("<") || part.endsWith(")")) {
                    versionEndExcluding = part.replace("<", "").replace(")", "").trim();
                } else if (part.startsWith("=")) {
                    versionStartIncluding = part.replace("=", "").trim();
                    versionEndIncluding = part.replace("=", "").trim();
                } else {
                    LOGGER.warn("Unable to determine version range " + part);
                }
            }

            VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(packageURL.getType(), packageURL.getNamespace(), packageURL.getName(),
                    versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
            if (vs == null) {
                vs = new VulnerableSoftware();
                vs.setVulnerable(true);
                vs.setPurlType(packageURL.getType());
                vs.setPurlNamespace(packageURL.getNamespace());
                vs.setPurlName(packageURL.getName());
                vs.setVersion(packageURL.getVersion());
                vs.setVersionStartIncluding(versionStartIncluding);
                vs.setVersionStartExcluding(versionStartExcluding);
                vs.setVersionEndIncluding(versionEndIncluding);
                vs.setVersionEndExcluding(versionEndExcluding);
            }
            vulnerableSoftwares.add(vs);
        }
        return vulnerableSoftwares;
    }
}
