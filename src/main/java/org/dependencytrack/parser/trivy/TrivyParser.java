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
package org.dependencytrack.parser.trivy;

import alpine.common.logging.Logger;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.trivy.model.CVSS;

import java.math.BigDecimal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import static org.apache.commons.lang3.StringUtils.trimToNull;

public class TrivyParser {

    private static final Logger LOGGER = Logger.getLogger(TrivyParser.class);

    public Vulnerability parse(org.dependencytrack.parser.trivy.model.Vulnerability data) {
        var vulnerability = new Vulnerability();
        vulnerability.setSource(Vulnerability.Source.resolve(data.getVulnerabilityID()));
        vulnerability.setPatchedVersions(data.getFixedVersion());

        // get the id of the data record (vulnerability)
        vulnerability.setVulnId(data.getVulnerabilityID());
        vulnerability.setTitle(data.getTitle());
        vulnerability.setDescription(data.getDescription());
        vulnerability.setSeverity(parseSeverity(data.getSeverity()));

        try {
            vulnerability.setPublished(parseDate(data.getPublishedDate()));
            vulnerability.setCreated(vulnerability.getPublished());
        } catch (ParseException ex) {
            LOGGER.warn("Unable to parse published date %s".formatted(data.getPublishedDate()), ex);
        }

        try {
            vulnerability.setUpdated(parseDate(data.getLastModifiedDate()));
        } catch (ParseException ex) {
            LOGGER.warn("Unable to parse last modified date %s".formatted(data.getLastModifiedDate()), ex);
        }

        vulnerability.setReferences(addReferences(data.getReferences()));

        // CWE
        for (String id : data.getCweIDS()) {
            final Cwe cwe = CweResolver.getInstance().lookup(id);
            if (cwe != null) {
                vulnerability.addCwe(cwe);
            }
        }

        vulnerability = setCvssScore(data.getCvss().get(data.getSeveritySource()), vulnerability);

        return vulnerability;
    }

    public Date parseDate(String input) throws ParseException {
        if (input != null) {
            String format = input.length() == 20 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
            SimpleDateFormat formatter = new SimpleDateFormat(format, Locale.ENGLISH);
            return formatter.parse(input);
        }
        return null;
    }

    public Severity parseSeverity(String severity) {

        if (severity != null) {
            if (severity.equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (severity.equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (severity.equalsIgnoreCase("MEDIUM")) {
                return Severity.MEDIUM;
            } else if (severity.equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            } else {
                return Severity.UNASSIGNED;
            }
        }
        return Severity.UNASSIGNED;
    }

    public Vulnerability setCvssScore(CVSS cvss, Vulnerability vulnerability) {
        if (cvss != null) {
            vulnerability.setCvssV2Vector(trimToNull(cvss.getV2Vector()));
            vulnerability.setCvssV3Vector(trimToNull(cvss.getV3Vector()));
            if (cvss.getV2Score() > 0.0) {
                vulnerability.setCvssV2BaseScore(BigDecimal.valueOf(cvss.getV2Score()));
            }
            if (cvss.getV3Score() > 0.0) {
                vulnerability.setCvssV3BaseScore(BigDecimal.valueOf(cvss.getV3Score()));
            }
        }

        return vulnerability;
    }

    public String addReferences(String[] references) {
        final StringBuilder sb = new StringBuilder();
        for (String reference : references) {
            if (reference != null) {
                sb.append("* [").append(reference).append("](").append(reference).append(")\n");
            }
        }
        return sb.toString();
    }
}
