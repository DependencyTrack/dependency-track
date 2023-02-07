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
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The GroupedFinding object is a metadata/value object that combines data from multiple tables. The object can
 * only be queried on, not updated or deleted. Modifications to data in the GroupedFinding object need to be made
 * to the original source object needing modified.
 *
 * @since 4.8.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GroupedFinding implements Serializable {

    private static final long serialVersionUID = 2246518534279822243L;

    public static final String QUERY = """
            SELECT
                "VULNERABILITY"."SOURCE",
                "VULNERABILITY"."VULNID",
                "VULNERABILITY"."TITLE",
                "VULNERABILITY"."SEVERITY",
                "FINDINGATTRIBUTION"."ANALYZERIDENTITY",
                "VULNERABILITY"."PUBLISHED",
                "VULNERABILITY"."CWES",
                "VULNERABILITY"."CVSSV3BASESCORE",
                COUNT(DISTINCT "PROJECT"."ID") AS "AFFECTED_PROJECT_COUNT",
                MIN("AFFECTEDVERSIONATTRIBUTION"."FIRST_SEEN") AS "FIRST_OCCURRENCE",
                MAX("AFFECTEDVERSIONATTRIBUTION"."LAST_SEEN") AS "LAST_OCCURRENCE"
            FROM "COMPONENT"
                INNER JOIN "COMPONENTS_VULNERABILITIES" ON ("COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID")
                INNER JOIN "VULNERABILITY" ON ("COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID")
                INNER JOIN "FINDINGATTRIBUTION" ON ("COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID") AND ("VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID")
                LEFT JOIN "ANALYSIS" ON ("COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID") AND ("VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID") AND ("COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID")
                INNER JOIN "PROJECT" ON ("COMPONENT"."PROJECT_ID" = "PROJECT"."ID")
                LEFT JOIN "AFFECTEDVERSIONATTRIBUTION" ON ("VULNERABILITY"."ID" = "AFFECTEDVERSIONATTRIBUTION"."VULNERABILITY")
            """;

    private Map<String, Object> vulnerability = new LinkedHashMap<>();
    private Map<String, Object> attribution = new LinkedHashMap<>();

    public GroupedFinding(Object ...o) {
        optValue(vulnerability, "source", o[0]);
        optValue(vulnerability, "vulnId", o[1]);
        optValue(vulnerability, "title", o[2]);
        optValue(vulnerability, "severity", o[3]);
        optValue(attribution, "analyzerIdentity", o[4]);
        optValue(vulnerability, "published", o[5]);
        optValue(vulnerability, "cwes", Finding.getCwes(o[6]));
        optValue(vulnerability, "cvssV3BaseScore", o[7]);
        optValue(vulnerability, "affectedProjectCount", o[8]);
        optValue(attribution, "firstOccurrence", o[9]);
        optValue(attribution, "lastOccurrence", o[10]);
    }

    public Map getVulnerability() {
        return vulnerability;
    }

    public Map getAttribution() {
        return attribution;
    }

    private void optValue(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

}
