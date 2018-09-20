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
import com.fasterxml.jackson.annotation.JsonProperty;
import org.dependencytrack.util.VulnerabilityUtil;
import java.io.Serializable;

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
            "\"VULNERABILITY\".\"SOURCE\" AS \"VULN_SOURCE\", " +
            "\"VULNERABILITY\".\"VULNID\" AS \"VULN_ID\", " +
            "\"VULNERABILITY\".\"UUID\" AS \"VULN_UUID\", " +
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

    private Object componentUuid;
    private Object name;
    private Object group;
    private Object version;
    private Object source;
    private Object vulnId;
    private Object vulnUuid;
    private Object severity;
    private Object severityRank;
    private Object cweId;
    private Object cweName;
    private Object state;

    @JsonProperty(value = "isSuppressed")
    private Object suppressed;

    /**
     * Constructs a new Finding object. The generic Object array passed as an argument is the
     * individual values for each row in a resultset. The order of these must match the order
     * of the columns being queried in {@link #QUERY}.
     * @param o An array of values specific to an individual row returned from {@link #QUERY}
     */
    public Finding(Object[] o) {
        this.componentUuid = o[0];
        this.name = o[1];
        this.group = o[2];
        this.version = o[3];
        this.source = o[4];
        this.vulnId = o[5];
        this.vulnUuid = o[6];

        final Severity severity = VulnerabilityUtil.getSeverity(o[7], o[8], o[9]);
        this.severity = severity.name();
        this.severityRank = severity.ordinal();

        this.cweId = o[10];
        this.cweName= o[11];
        this.state = o[12];
        this.suppressed = o[13];
    }

    public Object getComponentUuid() {
        return componentUuid;
    }

    public Object getName() {
        return name;
    }

    public Object getGroup() {
        return group;
    }

    public Object getVersion() {
        return version;
    }

    public Object getSource() {
        return source;
    }

    public Object getVulnId() {
        return vulnId;
    }

    public Object getVulnUuid() {
        return vulnUuid;
    }

    public Object getSeverity() {
        return severity;
    }

    public Object getSeverityRank() {
        return severityRank;
    }

    public Object getCweId() {
        return cweId;
    }

    public Object getCweName() {
        return cweName;
    }

    public Object getState() {
        return state;
    }

    public Object isSuppressed() {
        return suppressed;
    }
}
