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
package org.owasp.dependencytrack.tasks;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.event.framework.SingleThreadedEventService;
import alpine.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.event.VulnDbSyncEvent;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.persistence.QueryManager;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.Score;
import us.springett.vulndbdatamirror.parser.VulnDbParser;
import us.springett.vulndbdatamirror.parser.model.CvssV2Metric;
import us.springett.vulndbdatamirror.parser.model.CvssV3Metric;
import us.springett.vulndbdatamirror.parser.model.Results;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.Date;

/**
 * Subscriber task that performs synchronization with VulnDB mirrored data.
 * This task relies on an existing mirror generated from vulndb-data-mirror. The mirror must exist
 * in a 'vulndb' subdirectory of the Dependency-Track data directory. i.e.  ~/dependency-track/vulndb
 *
 * https://github.com/stevespringett/vulndb-data-mirror
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class VulnDbSyncTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(VulnDbSyncTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof VulnDbSyncEvent) {
            LOGGER.info("Starting VulnDB mirror synchronization task");
            final File vulndbDir = new File(Config.getInstance().getDataDirectorty(), "vulndb");
            if (!vulndbDir.exists()) {
                LOGGER.info("VulnDB mirror directory does not exist. Skipping.");
                return;
            }
            File[] files = vulndbDir.listFiles(
                    (dir, name) -> name.toLowerCase().startsWith("vulnerabilities_")
            );
            if (files != null) {
                for (File file : files) {
                    LOGGER.info("Parsing: " + file.getName());
                    VulnDbParser parser = new VulnDbParser();
                    try {
                        Results results = parser.parse(file, us.springett.vulndbdatamirror.parser.model.Vulnerability.class);
                        updateDatasource(results);
                    } catch (IOException ex) {
                        LOGGER.error("Error occurred parsing VulnDB payload: " + file.getName(), ex);
                    }
                }
            }
            SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
            LOGGER.info("VulnDB mirror synchronization task complete");
        }
    }

    /**
     * Synchronizes the VulnDB vulnerabilities with the internal Dependency-Track database.
     * @param results the results to synchronize
     */
    private void updateDatasource(Results results) {
        LOGGER.info("Updating datasource with VulnDB vulnerabilities");
        try (QueryManager qm = new QueryManager()) {
            for (Object o: results.getResults()) {
                if (o instanceof us.springett.vulndbdatamirror.parser.model.Vulnerability) {
                    us.springett.vulndbdatamirror.parser.model.Vulnerability vulnDbVuln = (us.springett.vulndbdatamirror.parser.model.Vulnerability)o;
                    org.owasp.dependencytrack.model.Vulnerability vulnerability = convert(qm, vulnDbVuln);
                    qm.synchronizeVulnerability(vulnerability, false);
                }
            }
        }
    }

    /**
     * Helper method that converts an VulnDB vulnerability object to a Dependency-Track vulnerability object.
     * @param vulnDbVuln the VulnDB vulnerability to convert
     * @return a Dependency-Track Vulnerability object
     */
    private org.owasp.dependencytrack.model.Vulnerability convert(QueryManager qm, us.springett.vulndbdatamirror.parser.model.Vulnerability vulnDbVuln) {
        final org.owasp.dependencytrack.model.Vulnerability vuln = new org.owasp.dependencytrack.model.Vulnerability();
        vuln.setSource(org.owasp.dependencytrack.model.Vulnerability.Source.VULNDB);
        vuln.setVulnId(sanitize(String.valueOf(vulnDbVuln.getId())));
        vuln.setTitle(sanitize(vulnDbVuln.getTitle()));


        /* Description */
        StringBuilder description = new StringBuilder();
        if (vulnDbVuln.getDescription() != null) {
            description.append(sanitize(vulnDbVuln.getDescription()));
        }
        if (vulnDbVuln.getTechnicalDescription() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.getTechnicalDescription()));
        }
        if (vulnDbVuln.getSolution() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.getSolution()));
        }
        if (vulnDbVuln.getManualNotes() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.getManualNotes()));
        }
        vuln.setDescription(description.toString());


        /* Dates */
        if (StringUtils.isNotBlank(vulnDbVuln.getDisclosureDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.getDisclosureDate());
            vuln.setCreated(Date.from(odt.toInstant()));
        }
        if (StringUtils.isNotBlank(vulnDbVuln.getDisclosureDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.getDisclosureDate());
            vuln.setPublished(Date.from(odt.toInstant()));
        }
        /*
        if (StringUtils.isNotBlank(vulnDbVuln.getUpdatedAt())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.getUpdatedAt());
            vuln.setUpdated(Date.from(odt.toInstant()));
        }
        */


        /* References */
        final StringBuilder references = new StringBuilder();
        for (us.springett.vulndbdatamirror.parser.model.ExternalReference reference : vulnDbVuln.getExtReferences()) {
            final String sType = sanitize(reference.getType());
            final String sValue = sanitize(reference.getValue());
            // Convert reference to Markdown format
            if (sValue != null && sValue.startsWith("http")) {
                references.append("* [").append(sValue).append("](").append(sValue).append(")\n");
            } else {
                references.append("* ").append(sValue).append(" (").append(sType).append(")\n");
            }
        }
        vuln.setReferences(references.toString());


        /* Credits */
        final StringBuilder credits = new StringBuilder();
        for (us.springett.vulndbdatamirror.parser.model.Author author : vulnDbVuln.getAuthors()) {
            final String name = sanitize(author.getName());
            final String company = sanitize(author.getCompany());
            if (name != null && company != null) {
                credits.append(name).append(" (").append(company).append(")").append(", ");
            } else {
                if (name != null) {
                    credits.append(name).append(", ");
                }
                if (company != null) {
                    credits.append(company).append(", ");
                }
            }
        }
        final String creditsText = credits.toString();
        if (creditsText.endsWith(", ")) {
            vuln.setCredits(StringUtils.trimToNull(creditsText.substring(0, creditsText.length() - 2)));
        }

        CvssV2 cvssV2;
        for (CvssV2Metric metric : vulnDbVuln.getCvssV2Metrics()) {
            cvssV2 = metric.toNormalizedMetric();
            Score score = cvssV2.calculateScore();
            vuln.setCvssV2Vector(cvssV2.getVector());
            vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
            vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
            vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            if (metric.getCveId() != null) {
                break; // Always prefer use of the NVD scoring, if available
            }
        }

        CvssV3 cvssV3;
        for (CvssV3Metric metric : vulnDbVuln.getCvssV3Metrics()) {
            cvssV3 = metric.toNormalizedMetric();
            Score score = cvssV3.calculateScore();
            vuln.setCvssV3Vector(cvssV3.getVector());
            vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
            vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
            vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            if (metric.getCveId() != null) {
                break; // Always prefer use of the NVD scoring, if available
            }
        }

        if (vulnDbVuln.getNvdAdditionalInfo() != null) {
            final String cweString = vulnDbVuln.getNvdAdditionalInfo().getCweId();
            if (cweString != null && cweString.startsWith("CWE-")) {
                try {
                    final int cweId = Integer.parseInt(cweString.substring(4, cweString.length()).trim());
                    final Cwe cwe = qm.getCweById(cweId);
                    vuln.setCwe(cwe);
                } catch (NumberFormatException e) {
                    LOGGER.error("Error parsing CWE ID: " + cweString, e);
                }
            }
        }

        return vuln;
    }

    /**
     * VulnDB data is known to have non-printable characters, unicode characters typically used for formatting,
     * and other characters that we do not want to import into the data model. This method will remove those
     * characters.
     *
     * @param input the String to sanitize
     * @return a sanitized String free of unwanted characters
     */
    private String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return StringUtils.trimToNull(input
                .replaceAll("\\u00AD", "") // (Soft Hyphen)
                .replaceAll("\\u200B", "") // (Zero Width Space)
                .replaceAll("\\u200E", "") // (Left-to-Right Mark)
                .replaceAll("\\u200F", "") // (Right-to-Left Mark)
                .replaceAll("\\u00A0", "") // (Non-Breaking Space)
                .replaceAll("\\uFEFF", "") // (Zero Width No-Break Space)
                .replaceAll("\\u007F", "") // (DELETE Control Character)
                .replaceAll("[\\u0000-\\u001F]", "") // (Control Characters)
                .replaceAll("[\\u0080-\\u009F]", "") // (C1 Control Characters)
        );
    }

}
