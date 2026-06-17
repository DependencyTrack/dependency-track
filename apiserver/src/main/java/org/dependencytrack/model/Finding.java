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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.jdbi.FindingDao;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;


/**
 * The Finding object is a metadata/value object that combines data from multiple tables. The object can
 * only be queried on, not updated or deleted. Modifications to data in the Finding object need to be made
 * to the original source object needing modified.
 *
 * @since 3.1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class Finding implements Serializable {

    private final UUID project;
    private final Map<String, Object> component = new LinkedHashMap<>();
    private final Map<String, Object> vulnerability = new LinkedHashMap<>();
    private final Map<String, Object> analysis = new LinkedHashMap<>();
    private final Map<String, Object> attribution = new LinkedHashMap<>();

    public Finding(final FindingDao.FindingRow findingRow) {
        this.project = findingRow.projectUuid();
        optValue(component, "uuid", findingRow.componentUuid());
        optValue(component, "name", findingRow.componentName());
        optValue(component, "group", findingRow.componentGroup());
        optValue(component, "version", findingRow.componentVersion());
        if (findingRow.componentPurl() != null) {
            optValue(component, "purl", findingRow.componentPurl());
        }
        optValue(component, "cpe", findingRow.componentCpe());
        optValue(component, "project", findingRow.projectUuid());
        optValue(component, "hasOccurrences", findingRow.componentHasOccurrences(), false);
        optValue(component, "scope", findingRow.componentScope());

        optValue(vulnerability, "uuid", findingRow.vulnUuid());
        optValue(vulnerability, "source", findingRow.vulnSource());
        optValue(vulnerability, "vulnId", findingRow.vulnId());
        optValue(vulnerability, "title", findingRow.vulnTitle());
        optValue(vulnerability, "subtitle", findingRow.vulnSubtitle());
        optValue(vulnerability, "description", findingRow.vulnDescription());
        optValue(vulnerability, "recommendation", findingRow.vulnRecommendation());
        optValue(vulnerability, "references", findingRow.vulnReferences());
        if (findingRow.vulnSeverity() != null) {
            final Severity severity = findingRow.vulnSeverity();
            optValue(vulnerability, "severity", severity.name());
            optValue(vulnerability, "severityRank", severity.ordinal());
        }
        optValue(vulnerability, "cvssV2BaseScore", findingRow.cvssV2BaseScore());
        optValue(vulnerability, "cvssV3BaseScore", findingRow.cvssV3BaseScore());
        optValue(vulnerability, "cvssV4Score", findingRow.cvssV4Score());
        optValue(vulnerability, "cvssV2Vector", findingRow.cvssV2Vector());
        optValue(vulnerability, "cvssV3Vector", findingRow.cvssV3Vector());
        optValue(vulnerability, "cvssV4Vector", findingRow.cvssV4Vector());
        optValue(vulnerability, "owaspLikelihoodScore", findingRow.owaspRRLikelihoodScore());
        optValue(vulnerability, "owaspTechnicalImpactScore", findingRow.owaspRRTechnicalImpactScore());
        optValue(vulnerability, "owaspBusinessImpactScore", findingRow.owaspRRBusinessImpactScore());
        optValue(vulnerability, "owaspRRVector", findingRow.owaspRRVector());
        optValue(vulnerability, "epssScore", findingRow.epssScore());
        optValue(vulnerability, "epssPercentile", findingRow.epssPercentile());
        optValue(vulnerability, "cwes", getCwes(findingRow.cwes()));
        addVulnerabilityAliases(findingRow.vulnAliasesJson());

        optValue(attribution, "analyzerIdentity", findingRow.analyzerIdentity());
        optValue(attribution, "attributedOn", Date.from(findingRow.attributed_on()));
        optValue(attribution, "alternateIdentifier", findingRow.alt_id());
        optValue(attribution, "referenceUrl", findingRow.reference_url());

        optValue(analysis, "state", findingRow.analysisState());
        optValue(analysis, "isSuppressed", findingRow.suppressed(), false);
        if (findingRow.vulnPublished() != null) {
            optValue(vulnerability, "published", Date.from(findingRow.vulnPublished()));
        }
        optValue(component, "projectName", findingRow.projectName());
        optValue(component, "projectVersion", findingRow.projectVersion());
    }

    public Map<String, Object> getComponent() {
        return component;
    }

    public Map<String, Object> getVulnerability() {
        return vulnerability;
    }

    public Map<String, Object> getAnalysis() {
        return analysis;
    }

    public Map<String, Object> getAttribution() {
        return attribution;
    }

    private void optValue(Map<String, Object> map, String key, Object value, boolean defaultValue) {
        if (value == null) {
            map.put(key, defaultValue);
        } else {
            map.put(key, value);
        }
    }

    private void optValue(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    static List<Cwe> getCwes(final List<Integer> cweIds) {
        if (cweIds == null || cweIds.isEmpty()) {
            return null;
        }
        final List<Cwe> cwes = new ArrayList<>();
        for (final var cweId : cweIds) {
            final Cwe cwe = CweResolver.getInstance().lookup(cweId);
            if (cwe != null) {
                cwes.add(cwe);
            }
        }
        if (cwes.isEmpty()) {
            return null;
        }
        return cwes;
    }

    public String getMatrix() {
        return project.toString() + ":" + component.get("uuid") + ":" + vulnerability.get("uuid");
    }

    public void addVulnerabilityAliases(List<VulnerabilityAlias> aliases) {
        final Set<Map<String, String>> uniqueAliases = new HashSet<>();
        if (aliases != null) {
            for (final VulnerabilityAlias alias : aliases) {
                Map<String, String> map = new HashMap<>();
                if (alias.getCveId() != null && !alias.getCveId().isBlank()) {
                    map.put("cveId", alias.getCveId());
                }
                if (alias.getGhsaId() != null && !alias.getGhsaId().isBlank()) {
                    map.put("ghsaId", alias.getGhsaId());
                }
                if (alias.getSonatypeId() != null && !alias.getSonatypeId().isBlank()) {
                    map.put("sonatypeId", alias.getSonatypeId());
                }
                if (alias.getOsvId() != null && !alias.getOsvId().isBlank()) {
                    map.put("osvId", alias.getOsvId());
                }
                if (alias.getSnykId() != null && !alias.getSnykId().isBlank()) {
                    map.put("snykId", alias.getSnykId());
                }
                if (alias.getVulnDbId() != null && !alias.getVulnDbId().isBlank()) {
                    map.put("vulnDbId", alias.getVulnDbId());
                }
                uniqueAliases.add(map);
            }
        }
        vulnerability.put("aliases",uniqueAliases);
    }
}