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

import alpine.crypto.DataEncryption;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.util.Pageable;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.http.HttpHeaders;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.event.OssIndexAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.ossindex.OssIndexParser;
import org.dependencytrack.parser.ossindex.model.ComponentReport;
import org.dependencytrack.parser.ossindex.model.ComponentReportVulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.json.JSONObject;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.Score;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using Sonatype OSS Index REST API.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
public class OssIndexAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final String API_BASE_URL = "https://ossindex.sonatype.org/api/v3/component-report";
    private static final Logger LOGGER = Logger.getLogger(OssIndexAnalysisTask.class);
    private String apiUsername;
    private String apiToken;

    public OssIndexAnalysisTask() {
        super(100, 5);
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof OssIndexAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED)) {
                return;
            }
            try (QueryManager qm = new QueryManager()) {
                final ConfigProperty apiUsernameProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_OSSINDEX_API_USERNAME.getGroupName(),
                        ConfigPropertyConstants.SCANNER_OSSINDEX_API_USERNAME.getPropertyName()
                );
                final ConfigProperty apiTokenProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_OSSINDEX_API_TOKEN.getGroupName(),
                        ConfigPropertyConstants.SCANNER_OSSINDEX_API_TOKEN.getPropertyName()
                );
                if (apiUsernameProperty == null || apiUsernameProperty.getPropertyValue() == null) {
                    LOGGER.warn("An API username has not been specified for use with OSS Index. Skipping");
                    return;
                }
                if (apiTokenProperty == null || apiTokenProperty.getPropertyValue() == null) {
                    LOGGER.warn("An API Token has not been specified for use with OSS Index. Skipping");
                    return;
                }
                try {
                    apiUsername = apiUsernameProperty.getPropertyValue();
                    apiToken = DataEncryption.decryptAsString(apiTokenProperty.getPropertyValue());
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the OSS Index API Token. Skipping", ex);
                    return;
                }
            }
            final OssIndexAnalysisEvent event = (OssIndexAnalysisEvent)e;
            LOGGER.info("Starting Sonatype OSS Index analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            } else {
                super.analyze();
            }
            LOGGER.info("Sonatype OSS Index analysis complete");
        }
    }

    /**
     * Determines if the {@link OssIndexAnalysisTask} is suitable for analysis based on the PackageURL.
     *
     * @param purl the PackageURL to analyze
     * @return true if OssIndexAnalysisTask should analyze, false if not
     */
    public boolean shouldAnalyze(final PackageURL purl) {
        return purl != null && !isCacheCurrent(Vulnerability.Source.OSSINDEX, API_BASE_URL, purl.toString());
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        final Pageable<Component> paginatedComponents = new Pageable<>(100, components);
        while (!paginatedComponents.isPaginationComplete()) {
            final List<String> coordinates = new ArrayList<>();
            final List<Component> paginatedList = paginatedComponents.getPaginatedList();
            for (final Component component: paginatedList) {
                if (shouldAnalyze(component.getPurl())) {
                    //coordinates.add(component.getPurl().canonicalize()); // todo: put this back when minimizePurl() is removed
                    coordinates.add(minimizePurl(component.getPurl()));
                }
            }
            if (CollectionUtils.isEmpty(coordinates)) {
                return;
            }
            final JSONObject json = new JSONObject();
            json.put("coordinates", coordinates);
            try {
                final List<ComponentReport> report = submit(json);
                processResults(report, paginatedList);
            } catch (UnirestException e) {
                LOGGER.error("An error occurred while analyzing", e);
            }
            LOGGER.info("Analyzing " + coordinates.size() + " component(s)");
            doThrottleDelay();
            paginatedComponents.nextPage();
        }
    }

    /**
     * Sonatype OSSIndex (as of December 2018) has an issue that fails to identify vulnerabilities when
     * HTTP POST is used and PackageURL is specified that contains qualifiers (and possibly a subpath).
     * Therefore, this method will return a String representation of a PackageURL without qualifier
     * or subpath. This method should be removed at a future date when OSSIndex resolves the issue.
     *
     * TODO: Delete this method and workaround for OSSIndex bug once Sonatype resolves it.
     * @since 3.4.0
     */
    @Deprecated
    private static String minimizePurl(final PackageURL purl) {
        String p = purl.canonicalize();
        if (p.contains("?")) {
            p = p.substring(0, p.lastIndexOf("?"));
        }
        if (p.contains("#")) {
            p = p.substring(0, p.lastIndexOf("#"));
        }
        return p;
    }

    /**
     * Submits the payload to the Sonatype OSS Index service
     */
    private List<ComponentReport> submit(final JSONObject payload) throws UnirestException {
        final UnirestInstance ui = UnirestFactory.getUnirestInstance();
        final HttpResponse<JsonNode> jsonResponse = ui.post(API_BASE_URL)
                .header(HttpHeaders.ACCEPT, "application/json")
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent())
                .basicAuth(apiUsername, apiToken)
                .body(payload)
                .asJson();
        if (jsonResponse.getStatus() == 200) {
            final OssIndexParser parser = new OssIndexParser();
            return parser.parse(jsonResponse.getBody());
        } else {
            LOGGER.warn("Received unexpected HTTP response " + jsonResponse.getStatus() + " " + jsonResponse.getStatusText());
        }
        return new ArrayList<>();
    }

    private void processResults(final List<ComponentReport> report, final List<Component> componentsScanned) {
        try (QueryManager qm = new QueryManager()) {
            for (final ComponentReport componentReport: report) {
                for (final Component component: componentsScanned) {
                    //final String componentPurl = component.getPurl().canonicalize(); // todo: put this back when minimizePurl() is removed
                    final String componentPurl = minimizePurl(component.getPurl());
                    final PackageURL sonatypePurl = oldPurlResolver(componentReport.getCoordinates());
                    if (componentPurl.equals(componentReport.getCoordinates()) ||
                            (sonatypePurl != null && componentPurl.equals(sonatypePurl.canonicalize()))) {
                        /*
                        Found the component
                         */
                        for (final ComponentReportVulnerability reportedVuln: componentReport.getVulnerabilities()) {
                            if (reportedVuln.getCve() != null) {
                                Vulnerability vulnerability = qm.getVulnerabilityByVulnId(
                                        Vulnerability.Source.NVD, reportedVuln.getCve());
                                if (vulnerability != null) {
                                    NotificationUtil.analyzeNotificationCriteria(vulnerability, component);
                                    qm.addVulnerability(vulnerability, component);
                                } else {
                                    /*
                                    The vulnerability reported by OSS Index is not in Dependency-Track yet. This could be
                                    due to timing issue or the vuln reported may be in a reserved state and not available
                                    through traditional feeds. Regardless, the vuln needs to be added to the database.
                                     */
                                    vulnerability = qm.createVulnerability(generateVulnerability(qm, reportedVuln), false);
                                    NotificationUtil.analyzeNotificationCriteria(vulnerability, component);
                                    qm.addVulnerability(vulnerability, component);
                                }
                            } else {
                                /*
                                The vulnerability is not from the NVD. Set the source to OSSINDEX
                                 */
                                Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.OSSINDEX, reportedVuln.getId());
                                if (vulnerability == null) {
                                    vulnerability = qm.createVulnerability(generateVulnerability(qm, reportedVuln), false);
                                }
                                NotificationUtil.analyzeNotificationCriteria(vulnerability, component);
                                qm.addVulnerability(vulnerability, component);
                            }
                        }
                        Event.dispatch(new MetricsUpdateEvent(component));
                    }
                    updateAnalysisCacheStats(qm, Vulnerability.Source.OSSINDEX, API_BASE_URL, component.getPurl().toString());
                }
            }
        }
    }

    /**
     * Generates a Dependency-Track vulnerability object from a Sonatype OSS ComponentReportVulnerability object.
     */
    private Vulnerability generateVulnerability(final QueryManager qm, final ComponentReportVulnerability reportedVuln) {
        final Vulnerability vulnerability = new Vulnerability();
        if (reportedVuln.getCve() != null) {
            vulnerability.setSource(Vulnerability.Source.NVD);
            vulnerability.setVulnId(reportedVuln.getCve());
        } else {
            vulnerability.setSource(Vulnerability.Source.OSSINDEX);
            vulnerability.setVulnId(reportedVuln.getId());
            vulnerability.setTitle(reportedVuln.getTitle());
        }
        vulnerability.setDescription(reportedVuln.getDescription());

        if (reportedVuln.getCwe() != null) {
            try {
                if (reportedVuln.getCwe().startsWith("CWE-")) {
                    final String cweId = reportedVuln.getCwe().substring(4);
                    final Cwe cwe = qm.getCweById(Integer.parseInt(cweId));
                    vulnerability.setCwe(cwe);
                } else {
                    final Cwe cwe = qm.getCweById(Integer.parseInt(reportedVuln.getCwe()));
                    vulnerability.setCwe(cwe);
                }
            } catch (NumberFormatException e) {
                LOGGER.error("An error occurred parsing the CWE ID of " + reportedVuln.getId());
            }
        }

        if (reportedVuln.getReference() != null) {
            vulnerability.setReferences("* [" + reportedVuln.getReference() + "](" + reportedVuln.getReference() + ")");
        }

        if (reportedVuln.getCvssVector() != null) {
            final Cvss cvss = Cvss.fromVector(reportedVuln.getCvssVector());
            if (cvss != null) {
                final Score score = cvss.calculateScore();
                if (cvss instanceof CvssV2) {
                    vulnerability.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                    vulnerability.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                    vulnerability.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                    vulnerability.setCvssV2Vector(cvss.getVector());
                } else if (cvss instanceof CvssV3) {
                    vulnerability.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                    vulnerability.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                    vulnerability.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                    vulnerability.setCvssV3Vector(cvss.getVector());
                }
            }
        }
        return vulnerability;
    }

    /**
     * Sonatype OSS Index currently uses an old/outdated version of the PackageURL specification.
     * Attempt to convert it into the current spec format and return it.
     */
    private PackageURL oldPurlResolver(String coordinates) {
        try {
            // Check if OSSIndex has updated their implementation or not
            if (coordinates.startsWith("pkg:")) {
                return new PackageURL(coordinates);
            }
            // Nope, they're still using the 'old' style. Force update it.
            return new PackageURL("pkg:" + coordinates.replaceFirst(":", "/"));
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }
}
