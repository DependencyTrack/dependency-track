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

import alpine.common.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.dependencytrack.common.Json;
import org.dependencytrack.parser.ossindex.model.ComponentReport;
import org.dependencytrack.parser.ossindex.model.ComponentReportVulnerability;

import java.io.IOException;
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
     * @param response the response to parse
     * @return an ComponentReport object
     * @throws IOException when reading the response fails
     */
    public List<ComponentReport> parse(final CloseableHttpResponse response) throws IOException {
        LOGGER.debug("Parsing JSON response");
        ArrayNode arr = Json.readHttpResponse(response, ArrayNode.class);
        final List<ComponentReport> componentReports = new ArrayList<>();
        for (int i = 0; i < arr.size(); i++) {
            final JsonNode object = arr.get(i);
            final ComponentReport componentReport = parse(object);
            componentReports.add(componentReport);
        }
        return componentReports;
    }

    private ComponentReport parse(final JsonNode object) {
        final ComponentReport componentReport = new ComponentReport();
        componentReport.setCoordinates(Json.optString(object, "coordinates", null));
        componentReport.setDescription(Json.optString(object, "description", null));
        componentReport.setReference(Json.optString(object, "references", null));
        final ArrayNode vulnerabilities = Json.optArray(object,"vulnerabilities", Json.newArray());
        for (int i = 0; i < vulnerabilities.size(); i++) {
            final JsonNode vulnObject = vulnerabilities.get(i);
            final ComponentReportVulnerability vulnerability = new ComponentReportVulnerability();
            vulnerability.setId(Json.optString(vulnObject, "id", null));
            vulnerability.setTitle(Json.optString(vulnObject, "title", null));
            vulnerability.setDescription(Json.optString(vulnObject, "description", null));
            vulnerability.setCvssScore(Json.optDouble(vulnObject, "cvssScore"));
            vulnerability.setCvssVector(Json.optString(vulnObject, "cvssVector", null));
            vulnerability.setCwe(Json.optString(vulnObject, "cwe", null));
            vulnerability.setCve(Json.optString(vulnObject, "cve", null));
            vulnerability.setReference(Json.optString(vulnObject, "reference", null));
            final ArrayNode externalRefsJSONArray = Json.optArray(vulnObject,"externalReferences", Json.newArray());
            final List<String> externalReferences = new ArrayList<>();
            for (int j = 0; j < externalRefsJSONArray.size(); j++) {
                externalReferences.add(externalRefsJSONArray.get(j).asText());
            }
            vulnerability.setExternalReferences(externalReferences);
            componentReport.addVulnerability(vulnerability);
        }
        return componentReport;
    }
}
