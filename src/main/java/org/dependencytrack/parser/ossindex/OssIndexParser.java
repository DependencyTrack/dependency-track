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
package org.dependencytrack.parser.ossindex;

import alpine.logging.Logger;
import kong.unirest.JsonNode;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
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
    public List<ComponentReport> parse(final JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");
        final List<ComponentReport> componentReports = new ArrayList<>();
        final JSONArray resultArray = jsonNode.getArray();
        for (int i = 0; i < resultArray.length(); i++) {
            final JSONObject object = resultArray.getJSONObject(i);
            final ComponentReport componentReport = parse(object);
            componentReports.add(componentReport);
        }
        return componentReports;
    }

    private ComponentReport parse(final JSONObject object) {
        final ComponentReport componentReport = new ComponentReport();
        componentReport.setCoordinates(object.optString("coordinates", null));
        componentReport.setDescription(object.optString("description", null));
        componentReport.setReference(object.optString("references", null));
        final JSONArray vulnerabilities = object.optJSONArray("vulnerabilities");
        for (int i = 0; i < vulnerabilities.length(); i++) {
            final JSONObject vulnObject = vulnerabilities.getJSONObject(i);
            final ComponentReportVulnerability vulnerability = new ComponentReportVulnerability();
            vulnerability.setId(vulnObject.optString("id", null));
            vulnerability.setTitle(vulnObject.optString("title", null));
            vulnerability.setDescription(vulnObject.optString("description", null));
            vulnerability.setCvssScore(vulnObject.optNumber("cvssScore", null));
            vulnerability.setCvssVector(vulnObject.optString("cvssVector", null));
            vulnerability.setCwe(vulnObject.optString("cwe", null));
            vulnerability.setCve(vulnObject.optString("cve", null));
            vulnerability.setReference(vulnObject.optString("reference", null));
            final JSONArray externalRefsJSONArray = vulnObject.optJSONArray("externalReferences");
            final List<String> externalReferences = new ArrayList<String>();
            for (int j = 0; j < externalRefsJSONArray.length(); j++) {
                externalReferences.add(externalRefsJSONArray.getString(j));
            }
            vulnerability.setExternalReferences(externalReferences);
            componentReport.addVulnerability(vulnerability);
        }
        return componentReport;
    }
}
