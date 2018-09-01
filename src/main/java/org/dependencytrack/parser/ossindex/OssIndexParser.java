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
package org.dependencytrack.parser.ossindex;

import alpine.logging.Logger;
import io.github.openunirest.http.JsonNode;
import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.parser.ossindex.model.ComponentReport;
import org.dependencytrack.parser.ossindex.model.ComponentReportVulnerability;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for Sonatype OSS Index response.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
public class OssIndexParser {

    private static final Logger LOGGER = Logger.getLogger(OssIndexParser.class);

    /**
     * Parses the JSON response from Sonatype OSS Index
     *
     * @param jsonNode the JSON node to parse
     * @return an ComponentReport object
     */
    public List<ComponentReport> parse(JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");
        List<ComponentReport> componentReports = new ArrayList<>();
        JSONArray resultArray = jsonNode.getArray();
        for (int i = 0; i < resultArray.length(); i++) {
            JSONObject object = resultArray.getJSONObject(i);
            ComponentReport componentReport = parse(object);
            componentReports.add(componentReport);
        }
        return componentReports;
    }

    private ComponentReport parse(JSONObject object) {
        final ComponentReport componentReport = new ComponentReport();
        componentReport.setCoordinates(object.optString("coordinates", null));
        componentReport.setDescription(object.optString("description", null));
        componentReport.setReference(object.optString("references", null));
        final JSONArray vulnerabilities = object.optJSONArray("vulnerabilities");
        for (int i = 0; i < vulnerabilities.length(); i++) {
            final JSONObject vulnObject = vulnerabilities.getJSONObject(i);
            ComponentReportVulnerability vulnerability = new ComponentReportVulnerability();
            vulnerability.setId(vulnObject.optString("id", null));
            vulnerability.setTitle(vulnObject.optString("title", null));
            vulnerability.setDescription(vulnObject.optString("description", null));
            vulnerability.setCvssScore(vulnObject.optNumber("cvssScore", null));
            vulnerability.setCvssVector(vulnObject.optString("cvssVector", null));
            vulnerability.setCwe(vulnObject.optString("cwe", null));
            vulnerability.setCve(vulnObject.optString("cve", null));
            vulnerability.setReference(vulnObject.optString("reference", null));
            componentReport.addVulnerability(vulnerability);
        }
        return componentReport;
    }
}
