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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.dependencytrack.util.VulnerabilityUtil;
import java.io.Serializable;
import java.util.LinkedHashMap;
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
            "\"COMPONENT\".\"UUID\" AS \"COMPONENT_UUID\", " +
            "\"COMPONENT\".\"NAME\" AS \"COMPONENT_NAME\", " +
            "\"COMPONENT\".\"GROUP\" AS \"COMPONENT_GROUP\", " +
            "\"COMPONENT\".\"VERSION\" AS \"COMPONENT_VERSION\", " +
            "\"COMPONENT\".\"PURL\" AS \"COMPONENT_PURL\", " +
            "\"VULNERABILITY\".\"UUID\" AS \"VULN_UUID\", " +
            "\"VULNERABILITY\".\"SOURCE\" AS \"VULN_SOURCE\", " +
            "\"VULNERABILITY\".\"VULNID\" AS \"VULN_ID\", " +
            "\"VULNERABILITY\".\"TITLE\" AS \"VULN_TITLE\", " +
            "\"VULNERABILITY\".\"SUBTITLE\" AS \"VULN_SUBTITLE\", " +
            "\"VULNERABILITY\".\"DESCRIPTION\" AS \"VULN_DESCRIPTION\", " +
            "\"VULNERABILITY\".\"RECOMMENDATION\" AS \"VULN_RECOMMENDATION\", " +
            "\"VULNERABILITY\".\"SEVERITY\" AS \"VULN_SEVERITY\", " +
            "\"VULNERABILITY\".\"CVSSV2BASESCORE\" AS \"VULN_CVSSV2BASESCORE\", " +
            "\"VULNERABILITY\".\"CVSSV3BASESCORE\" AS \"VULN_CVSSV3BASESCORE\", " +
            "\"CWE\".\"CWEID\" AS \"CWE_ID\", " +
            "\"CWE\".\"NAME\" AS \"CWE_NAME\", " +
            "\"ANALYSIS\".\"STATE\" AS \"ANALYSIS_STATE\", " +
            "\"ANALYSIS\".\"SUPPRESSED\" AS \"ANALYSIS_SUPPRESSED\" " +
            "FROM \"COMPONENT\" " +
            "INNER JOIN \"DEPENDENCY\" ON (\"COMPONENT\".\"ID\" = \"DEPENDENCY\".\"COMPONENT_ID\") " +
            "INNER JOIN \"COMPONENTS_VULNERABILITIES\" ON (\"DEPENDENCY\".\"COMPONENT_ID\" = \"COMPONENTS_VULNERABILITIES\".\"COMPONENT_ID\") " +
            "INNER JOIN \"VULNERABILITY\" ON (\"COMPONENTS_VULNERABILITIES\".\"VULNERABILITY_ID\" = \"VULNERABILITY\".\"ID\") " +
            "LEFT JOIN \"CWE\"  ON (\"VULNERABILITY\".\"CWE\" = \"CWE\".\"ID\") " +
            "LEFT JOIN \"ANALYSIS\" ON (\"COMPONENT\".\"ID\" = \"ANALYSIS\".\"COMPONENT_ID\") AND (\"VULNERABILITY\".\"ID\" = \"ANALYSIS\".\"VULNERABILITY_ID\") AND (\"DEPENDENCY\".\"PROJECT_ID\" = \"ANALYSIS\".\"PROJECT_ID\") " +
            "WHERE \"DEPENDENCY\".\"PROJECT_ID\" = ?";

    private UUID project;
    private Map<String, Object> component = new LinkedHashMap<>();
    private Map<String, Object> vulnerability = new LinkedHashMap<>();
    private Map<String, Object> analysis = new LinkedHashMap<>();

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

        optValue(vulnerability, "uuid", o[5]);
        optValue(vulnerability, "source", o[6]);
        optValue(vulnerability, "vulnId", o[7]);
        optValue(vulnerability, "title", o[8]);
        optValue(vulnerability, "subtitle", o[9]);
        //optValue(vulnerability, "description", o[10]); // CLOB - handle this in QueryManager
        //optValue(vulnerability, "recommendation", o[11]); // CLOB - handle this in QueryManager
        final Severity severity = VulnerabilityUtil.getSeverity(o[12], o[13], o[14]);
        optValue(vulnerability, "severity", severity.name());
        optValue(vulnerability, "severityRank", severity.ordinal());
        optValue(vulnerability, "cweId", o[15]);
        optValue(vulnerability, "cweName", o[16]);

        optValue(analysis, "state", o[17]);
        optValue(analysis, "isSuppressed", o[18], false);
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

    public String getMatrix() {
        return project.toString() + ":" + component.get("uuid") + ":" + vulnerability.get("uuid");
    }

}
