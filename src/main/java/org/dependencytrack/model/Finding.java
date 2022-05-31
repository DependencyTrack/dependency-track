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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.util.VulnerabilityUtil;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
    public static final String QUERY = "SELECT " +
            "\"COMPONENT\".\"UUID\"," +
            "\"COMPONENT\".\"NAME\"," +
            "\"COMPONENT\".\"GROUP\"," +
            "\"COMPONENT\".\"VERSION\"," +
            "\"COMPONENT\".\"PURL\"," +
            "\"COMPONENT\".\"CPE\"," +
            "\"VULNERABILITY\".\"UUID\"," +
            "\"VULNERABILITY\".\"SOURCE\"," +
            "\"VULNERABILITY\".\"VULNID\"," +
            "\"VULNERABILITY\".\"TITLE\"," +
            "\"VULNERABILITY\".\"SUBTITLE\"," +
            "\"VULNERABILITY\".\"DESCRIPTION\"," +
            "\"VULNERABILITY\".\"RECOMMENDATION\"," +
            "\"VULNERABILITY\".\"SEVERITY\"," +
            "\"VULNERABILITY\".\"CVSSV2BASESCORE\"," +
            "\"VULNERABILITY\".\"CVSSV3BASESCORE\"," +
            "\"VULNERABILITY\".\"EPSSSCORE\"," +
            "\"VULNERABILITY\".\"EPSSPERCENTILE\"," +
            "\"VULNERABILITY\".\"CWES\"," +
            "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\"," +
            "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"," +
            "\"FINDINGATTRIBUTION\".\"ALT_ID\"," +
            "\"FINDINGATTRIBUTION\".\"REFERENCE_URL\"," +
            "\"ANALYSIS\".\"STATE\"," +
            "\"ANALYSIS\".\"SUPPRESSED\" " +
            "FROM \"COMPONENT\" " +
            "INNER JOIN \"COMPONENTS_VULNERABILITIES\" ON (\"COMPONENT\".\"ID\" = \"COMPONENTS_VULNERABILITIES\".\"COMPONENT_ID\") " +
            "INNER JOIN \"VULNERABILITY\" ON (\"COMPONENTS_VULNERABILITIES\".\"VULNERABILITY_ID\" = \"VULNERABILITY\".\"ID\") " +
            "INNER JOIN \"FINDINGATTRIBUTION\" ON (\"COMPONENT\".\"ID\" = \"FINDINGATTRIBUTION\".\"COMPONENT_ID\") AND (\"VULNERABILITY\".\"ID\" = \"FINDINGATTRIBUTION\".\"VULNERABILITY_ID\")" +
            "LEFT JOIN \"ANALYSIS\" ON (\"COMPONENT\".\"ID\" = \"ANALYSIS\".\"COMPONENT_ID\") AND (\"VULNERABILITY\".\"ID\" = \"ANALYSIS\".\"VULNERABILITY_ID\") AND (\"COMPONENT\".\"PROJECT_ID\" = \"ANALYSIS\".\"PROJECT_ID\") " +
            "WHERE \"COMPONENT\".\"PROJECT_ID\" = ?";

    private UUID project;
    private Map<String, Object> component = new LinkedHashMap<>();
    private Map<String, Object> vulnerability = new LinkedHashMap<>();
    private Map<String, Object> analysis = new LinkedHashMap<>();
    private Map<String, Object> attribution = new LinkedHashMap<>();

    /**
     * Constructs a new Finding object. The generic Object array passed as an argument is the
     * individual values for each row in a resultset. The order of these must match the order
     * of the columns being queried in {@link #QUERY}.
     * @param o An array of values specific to an individual row returned from {@link #QUERY}
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
        //optValue(vulnerability, "description", o[11]); // CLOB - handle this in QueryManager
        //optValue(vulnerability, "recommendation", o[12]); // CLOB - handle this in QueryManager
        final Severity severity = VulnerabilityUtil.getSeverity(o[13], o[14], o[15]);
        optValue(vulnerability, "cvssV2BaseScore", o[14]);
        optValue(vulnerability, "cvssV3BaseScore", o[15]);
        optValue(vulnerability, "severity", severity.name());
        optValue(vulnerability, "severityRank", severity.ordinal());
        optValue(vulnerability, "epssScore", o[16]);
        optValue(vulnerability, "epssPercentile", o[17]);
        final List<Cwe> cwes = getCwes(o[18]);
        if (cwes != null && !cwes.isEmpty()) {
            // Ensure backwards-compatibility with DT < 4.5.0. Remove this in v5!
            optValue(vulnerability, "cweId", cwes.get(0).getCweId());
            optValue(vulnerability, "cweName", cwes.get(0).getName());
        }
        optValue(vulnerability, "cwes", cwes);
        optValue(attribution, "analyzerIdentity", o[19]);
        optValue(attribution, "attributedOn", o[20]);
        optValue(attribution, "alternateIdentifier", o[21]);
        optValue(attribution, "referenceUrl", o[22]);

        optValue(analysis, "state", o[23]);
        optValue(analysis, "isSuppressed", o[24], false);
    }

    public Map getComponent() {
        return component;
    }

    public Map getVulnerability() {
        return vulnerability;
    }

    public Map getAnalysis() {
        return analysis;
    }

    public Map getAttribution() {
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

    private List<Cwe> getCwes(final Object value) {
        if (value instanceof String) {
            final String cweIds = (String)value;
            if (StringUtils.isBlank(cweIds)) {
                return null;
            }
            final List<Cwe> cwes = new ArrayList<>();
            for (final String s : cweIds.split(",")) {
                final Cwe cwe = CweResolver.getInstance().lookup(Integer.valueOf(s));
                if (cwe != null) {
                    cwes.add(cwe);
                }
            }
            return cwes;
        } else {
            return null;
        }
    }

    public String getMatrix() {
        return project.toString() + ":" + component.get("uuid") + ":" + vulnerability.get("uuid");
    }

}
