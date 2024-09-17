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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import trivy.proto.common.CVSS;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.trimToNull;

public class TrivyParser {

    public Vulnerability parse(trivy.proto.common.Vulnerability data) {
        var vulnerability = new Vulnerability();
        vulnerability.setSource(Vulnerability.Source.resolve(data.getVulnerabilityId()));
        vulnerability.setPatchedVersions(data.getFixedVersion());

        // get the id of the data record (vulnerability)
        vulnerability.setVulnId(data.getVulnerabilityId());
        vulnerability.setTitle(data.getTitle());
        vulnerability.setDescription(data.getDescription());
        vulnerability.setSeverity(parseSeverity(data.getSeverity()));

        if (data.hasPublishedDate()) {
            vulnerability.setPublished(new Date(Timestamps.toMillis(data.getPublishedDate())));
            vulnerability.setCreated(vulnerability.getPublished());
        }

        if (data.hasLastModifiedDate()) {
            vulnerability.setUpdated(new Date(Timestamps.toMillis(data.getLastModifiedDate())));
        }

        vulnerability.setReferences(addReferences(data.getReferencesList()));

        // CWE
        for (String id : data.getCweIdsList()) {
            final Cwe cwe = CweResolver.getInstance().lookup(id);
            if (cwe != null) {
                vulnerability.addCwe(cwe);
            }
        }

        vulnerability = setCvssScore(data.getCvssMap().get(data.getSeveritySource()), vulnerability);

        return vulnerability;
    }

    public Severity parseSeverity(trivy.proto.common.Severity severity) {
        return switch (severity) {
            case CRITICAL -> Severity.CRITICAL;
            case HIGH -> Severity.HIGH;
            case MEDIUM -> Severity.MEDIUM;
            case LOW -> Severity.LOW;
            default -> Severity.UNASSIGNED;
        };
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

    public String addReferences(List<String> references) {
        final StringBuilder sb = new StringBuilder();
        for (String reference : references) {
            if (reference != null) {
                sb.append("* [").append(reference).append("](").append(reference).append(")\n");
            }
        }
        return sb.toString();
    }
}
