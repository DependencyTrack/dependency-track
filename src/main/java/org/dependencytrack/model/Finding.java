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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigDecimal;
import java.sql.Clob;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.util.VulnerabilityUtil;

import com.fasterxml.jackson.annotation.JsonInclude;


/**
 * The Finding object is a metadata/value object that combines data from multiple tables. The object can
 * only be queried on, not updated or deleted. Modifications to data in the Finding object need to be made
 * to the original source object needing modified.
 *
 * @since 3.1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Finding implements Serializable {

    private static final long serialVersionUID = 5313521394432526986L;

    /*
     * This statement works on Microsoft SQL Server, MySQL, and PostgreSQL. Due to the standardization
     * of upper-case table and column names in Dependency-Track, every identifier needs to be wrapped
     * in double quotes to satisfy PostgreSQL case-sensitive requirements. This also places a requirement
     * on ANSI_QUOTES mode being enabled in MySQL. SQL Server works regardless and is just happy to be invited :-)
     */
    // language=SQL
    public static final String QUERY = """
            SELECT "COMPONENT"."UUID"
                 , "COMPONENT"."NAME"
                 , "COMPONENT"."GROUP"
                 , "COMPONENT"."VERSION"
                 , "COMPONENT"."PURL"
                 , "COMPONENT"."CPE"
                 , "VULNERABILITY"."UUID"
                 , "VULNERABILITY"."SOURCE"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE"
                 , "VULNERABILITY"."SUBTITLE"
                 , "VULNERABILITY"."DESCRIPTION"
                 , "VULNERABILITY"."RECOMMENDATION"
                 , "VULNERABILITY"."SEVERITY"
                 , "VULNERABILITY"."CVSSV2BASESCORE"
                 , "VULNERABILITY"."CVSSV3BASESCORE"
                 , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                 , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                 , "VULNERABILITY"."EPSSSCORE"
                 , "VULNERABILITY"."EPSSPERCENTILE"
                 , "VULNERABILITY"."CWES"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE"
                 , "ANALYSIS"."SUPPRESSED"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS"
                ON "COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
             WHERE "COMPONENT"."PROJECT_ID" = :projectId
               AND (:includeSuppressed = :true OR "ANALYSIS"."SUPPRESSED" IS NULL OR "ANALYSIS"."SUPPRESSED" = :false)
            """;

    // language=SQL
    public static final String QUERY_ALL_FINDINGS = """
            SELECT "COMPONENT"."UUID"
                 , "COMPONENT"."NAME"
                 , "COMPONENT"."GROUP"
                 , "COMPONENT"."VERSION"
                 , "COMPONENT"."PURL"
                 , "COMPONENT"."CPE"
                 , "VULNERABILITY"."UUID"
                 , "VULNERABILITY"."SOURCE"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE"
                 , "VULNERABILITY"."SUBTITLE"
                 , "VULNERABILITY"."DESCRIPTION"
                 , "VULNERABILITY"."RECOMMENDATION"
                 , "VULNERABILITY"."SEVERITY"
                 , "VULNERABILITY"."CVSSV2BASESCORE"
                 , "VULNERABILITY"."CVSSV3BASESCORE"
                 , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                 , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                 , "VULNERABILITY"."EPSSSCORE"
                 , "VULNERABILITY"."EPSSPERCENTILE"
                 , "VULNERABILITY"."CWES"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE"
                 , "ANALYSIS"."SUPPRESSED"
                 , "VULNERABILITY"."PUBLISHED"
                 , "PROJECT"."UUID"
                 , "PROJECT"."NAME"
                 , "PROJECT"."VERSION"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS"
                ON "COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
             INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
            """;

    private final UUID project;
    private final Map<String, Object> component = new LinkedHashMap<>();
    private final Map<String, Object> vulnerability = new LinkedHashMap<>();
    private final Map<String, Object> analysis = new LinkedHashMap<>();
    private final Map<String, Object> attribution = new LinkedHashMap<>();

    /**
     * Constructs a new Finding object. The generic Object array passed as an argument is the
     * individual values for each row in a resultset. The order of these must match the order
     * of the columns being queried in {@link #QUERY} or {@link #QUERY_ALL_FINDINGS}.
     * @param o An array of values specific to an individual row returned from {@link #QUERY} or {@link #QUERY_ALL_FINDINGS}
     */
    public Finding(UUID project, Object... o) {
        this.project = project;
        optValue(component, "uuid", o[0]);
        optValue(component, "name", o[1]);
        optValue(component, "group", o[2]);
        optValue(component, "version", o[3]);
        optValue(component, "purl", o[4]);
        optValue(component, "cpe", o[5]);
        optValue(component, "project", project.toString());

        optValue(vulnerability, "uuid", o[6]);
        optValue(vulnerability, "source", o[7]);
        optValue(vulnerability, "vulnId", o[8]);
        optValue(vulnerability, "title", o[9]);
        optValue(vulnerability, "subtitle", o[10]);
        if (o[11] instanceof final Clob clob) {
            optValue(vulnerability, "description", toString(clob));
        } else {
            optValue(vulnerability, "description", o[11]);
        }
        if (o[12] instanceof final Clob clob) {
            optValue(vulnerability, "recommendation", toString(clob));
        } else {
            optValue(vulnerability, "recommendation", o[12]);
        }
        final Severity severity = VulnerabilityUtil.getSeverity(o[13], (BigDecimal) o[14], (BigDecimal) o[15], (BigDecimal) o[16], (BigDecimal) o[17], (BigDecimal) o[18]);
        optValue(vulnerability, "cvssV2BaseScore", o[14]);
        optValue(vulnerability, "cvssV3BaseScore", o[15]);
        optValue(vulnerability, "owaspLikelihoodScore", o[16]);
        optValue(vulnerability, "owaspTechnicalImpactScore", o[17]);
        optValue(vulnerability, "owaspBusinessImpactScore", o[18]);
        optValue(vulnerability, "severity", severity.name());
        optValue(vulnerability, "severityRank", severity.ordinal());
        optValue(vulnerability, "epssScore", o[19]);
        optValue(vulnerability, "epssPercentile", o[20]);
        final List<Cwe> cwes = getCwes(o[21]);
        if (cwes != null && !cwes.isEmpty()) {
            // Ensure backwards-compatibility with DT < 4.5.0. Remove this in v5!
            optValue(vulnerability, "cweId", cwes.get(0).getCweId());
            optValue(vulnerability, "cweName", cwes.get(0).getName());
        }
        optValue(vulnerability, "cwes", cwes);
        optValue(attribution, "analyzerIdentity", o[22]);
        optValue(attribution, "attributedOn", o[23]);
        optValue(attribution, "alternateIdentifier", o[24]);
        optValue(attribution, "referenceUrl", o[25]);

        optValue(analysis, "state", o[26]);
        optValue(analysis, "isSuppressed", o[27], false);
        if (o.length > 30) {
            optValue(vulnerability, "published", o[28]);
            optValue(component, "projectName", o[30]);
            optValue(component, "projectVersion", o[31]);
        }
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

    static List<Cwe> getCwes(final Object value) {
        if (value instanceof final String cweIds) {
            if (StringUtils.isBlank(cweIds)) {
                return null;
            }
            final List<Cwe> cwes = new ArrayList<>();
            for (final String s : cweIds.split(",")) {
                if (StringUtils.isNumeric(s)) {
                    final Cwe cwe = CweResolver.getInstance().lookup(Integer.valueOf(s));
                    if (cwe != null) {
                        cwes.add(cwe);
                    }
                }
            }
            if (cwes.isEmpty()) {
                return null;
            }
            return cwes;
        } else {
            return null;
        }
    }

    public String getMatrix() {
        return project.toString() + ":" + component.get("uuid") + ":" + vulnerability.get("uuid");
    }

    public void addVulnerabilityAliases(List<VulnerabilityAlias> aliases) {
        final Set<Map<String, String>> uniqueAliases = new HashSet<>();
        for (final VulnerabilityAlias alias : aliases) {
            Map<String,String> map = new HashMap<>();
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
            if (alias.getDrupalId() != null && !alias.getDrupalId().isBlank()) {
                map.put("drupalId", alias.getDrupalId());
            }
            if (alias.getComposerId() != null && !alias.getComposerId().isBlank()) {
                map.put("composerId", alias.getComposerId());
            }
            uniqueAliases.add(map);
        }
        vulnerability.put("aliases",uniqueAliases);
    }

    private static String toString(final Clob clob) {
        if (clob == null) {
            return null;
        }

        try (final var reader = new BufferedReader(clob.getCharacterStream())) {
            return IOUtils.toString(reader);
        } catch (IOException | SQLException e) {
            throw new RuntimeException("Failed to read CLOB value", e);
        }
    }

}
