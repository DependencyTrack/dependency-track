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
package org.dependencytrack.parser.vulndb;

import alpine.common.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.vulndb.model.Author;
import org.dependencytrack.parser.vulndb.model.CvssV2Metric;
import org.dependencytrack.parser.vulndb.model.CvssV3Metric;
import org.dependencytrack.parser.vulndb.model.ExternalReference;
import org.dependencytrack.persistence.QueryManager;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.Score;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.Date;

/**
 * Utility class that converts various VulnDB to Dependency-Track models.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public final class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private constructor.
     */
    private ModelConverter() {
    }

    /**
     * Helper method that converts an VulnDB vulnerability object to a Dependency-Track vulnerability object.
     *
     * @param vulnDbVuln the VulnDB vulnerability to convert
     * @return a Dependency-Track Vulnerability object
     */
    public static Vulnerability convert(final QueryManager qm, final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln) {
        final org.dependencytrack.model.Vulnerability vuln = new org.dependencytrack.model.Vulnerability();
        vuln.setSource(org.dependencytrack.model.Vulnerability.Source.VULNDB);
        vuln.setVulnId(sanitize(String.valueOf(vulnDbVuln.id())));
        vuln.setTitle(sanitize(vulnDbVuln.title()));

        /* Description */
        final StringBuilder description = new StringBuilder();
        if (vulnDbVuln.description() != null) {
            description.append(sanitize(vulnDbVuln.description()));
        }
        if (vulnDbVuln.technicalDescription() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.technicalDescription()));
        }
        if (vulnDbVuln.solution() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.solution()));
        }
        if (vulnDbVuln.manualNotes() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.manualNotes()));
        }
        vuln.setDescription(description.toString());


        /* Dates */
        if (StringUtils.isNotBlank(vulnDbVuln.disclosureDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.disclosureDate());
            vuln.setCreated(Date.from(odt.toInstant()));
        }
        if (StringUtils.isNotBlank(vulnDbVuln.disclosureDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.disclosureDate());
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
        for (final ExternalReference reference : vulnDbVuln.extReferences()) {
            final String sType = sanitize(reference.type());
            final String sValue = sanitize(reference.value());
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
        for (final Author author : vulnDbVuln.authors()) {
            final String name = sanitize(author.name());
            final String company = sanitize(author.company());
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
        for (final CvssV2Metric metric : vulnDbVuln.cvssV2Metrics()) {
            cvssV2 = toNormalizedMetric(metric);
            final Score score = cvssV2.calculateScore();
            vuln.setCvssV2Vector(cvssV2.getVector());
            vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
            vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
            vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            if (metric.cveId() != null) {
                break; // Always prefer use of the NVD scoring, if available
            }
        }

        CvssV3 cvssV3;
        for (final CvssV3Metric metric : vulnDbVuln.cvssV3Metrics()) {
            cvssV3 = toNormalizedMetric(metric);
            final Score score = cvssV3.calculateScore();
            vuln.setCvssV3Vector(cvssV3.getVector());
            vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
            vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
            vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
            if (metric.cveId() != null) {
                break; // Always prefer use of the NVD scoring, if available
            }
        }

        if (vulnDbVuln.nvdAdditionalInfo() != null) {
            final String cweString = vulnDbVuln.nvdAdditionalInfo().cweId();
            if (cweString != null && cweString.startsWith("CWE-")) {
                final Cwe cwe = CweResolver.getInstance().resolve(qm, cweString);
                if (cwe != null) {
                    vuln.addCwe(cwe);
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
    private static String sanitize(final String input) {
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

    public static CvssV2 toNormalizedMetric(CvssV2Metric metric) {
        CvssV2 cvss = new CvssV2();
        if (!"ADJACENT_NETWORK" .equals(metric.accessVector()) && !"ADJACENT" .equals(metric.accessVector())) {
            if ("LOCAL" .equals(metric.accessVector())) {
                cvss.attackVector(CvssV2.AttackVector.LOCAL);
            } else if ("NETWORK" .equals(metric.accessVector())) {
                cvss.attackVector(CvssV2.AttackVector.NETWORK);
            }
        } else {
            cvss.attackVector(CvssV2.AttackVector.ADJACENT);
        }

        if ("SINGLE_INSTANCE" .equals(metric.authentication())) {
            cvss.authentication(CvssV2.Authentication.SINGLE);
        } else if ("MULTIPLE_INSTANCES" .equals(metric.authentication())) {
            cvss.authentication(CvssV2.Authentication.MULTIPLE);
        } else if ("NONE" .equals(metric.authentication())) {
            cvss.authentication(CvssV2.Authentication.NONE);
        }

        cvss.attackComplexity(CvssV2.AttackComplexity.valueOf(metric.accessComplexity()));
        cvss.confidentiality(CvssV2.CIA.valueOf(metric.confidentialityImpact()));
        cvss.integrity(CvssV2.CIA.valueOf(metric.integrityImpact()));
        cvss.availability(CvssV2.CIA.valueOf(metric.availabilityImpact()));
        return cvss;
    }

    public static CvssV3 toNormalizedMetric(CvssV3Metric metric) {
        CvssV3 cvss = new CvssV3();
        if (!"ADJACENT_NETWORK" .equals(metric.attackVector()) && !"ADJACENT" .equals(metric.attackVector())) {
            if ("LOCAL" .equals(metric.attackVector())) {
                cvss.attackVector(CvssV3.AttackVector.LOCAL);
            } else if ("NETWORK" .equals(metric.attackVector())) {
                cvss.attackVector(CvssV3.AttackVector.NETWORK);
            } else if ("PHYSICAL" .equals(metric.attackVector())) {
                cvss.attackVector(CvssV3.AttackVector.PHYSICAL);
            }
        } else {
            cvss.attackVector(CvssV3.AttackVector.ADJACENT);
        }

        cvss.attackComplexity(CvssV3.AttackComplexity.valueOf(metric.attackComplexity()));
        cvss.privilegesRequired(CvssV3.PrivilegesRequired.valueOf(metric.privilegesRequired()));
        cvss.userInteraction(CvssV3.UserInteraction.valueOf(metric.userInteraction()));
        cvss.scope(CvssV3.Scope.valueOf(metric.scope()));
        cvss.confidentiality(CvssV3.CIA.valueOf(metric.confidentialityImpact()));
        cvss.integrity(CvssV3.CIA.valueOf(metric.integrityImpact()));
        cvss.availability(CvssV3.CIA.valueOf(metric.availabilityImpact()));
        return cvss;
    }
}
