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
package org.dependencytrack.parser.snyk;

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.SnykCvssSource;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.snyk.model.SnykError;
import org.dependencytrack.persistence.QueryManager;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;

public class SnykParser {

    private static final Logger LOGGER = Logger.getLogger(SnykParser.class);

    public Vulnerability parse(JSONArray data, QueryManager qm, String purl, int count) {
        Vulnerability synchronizedVulnerability = new Vulnerability();
        Vulnerability vulnerability = new Vulnerability();
        List<VulnerableSoftware> vsList = new ArrayList<>();
        vulnerability.setSource(Vulnerability.Source.SNYK);
        // get the id of the data record (vulnerability)
        vulnerability.setVulnId(data.optJSONObject(count).optString("id", null));
        final JSONObject vulnAttributes = data.optJSONObject(count).optJSONObject("attributes");
        if (vulnAttributes != null && vulnAttributes.optString("type").equalsIgnoreCase("package_vulnerability")) {
            // get the references of the data record (vulnerability)
            final JSONObject slots = vulnAttributes.optJSONObject("slots");
            if (slots != null && slots.optJSONArray("references") != null) {
                vulnerability.setReferences(addReferences(slots));
            }
            vulnerability.setTitle(vulnAttributes.optString("title", null));
            vulnerability.setDescription(vulnAttributes.optString("description", null));
            vulnerability.setCreated(Date.from(jsonStringToTimestamp(vulnAttributes.optString("created_at")).toInstant()));
            vulnerability.setUpdated(Date.from(jsonStringToTimestamp(vulnAttributes.optString("updated_at")).toInstant()));
            final JSONArray problems = vulnAttributes.optJSONArray("problems");
            if (problems != null) {
                vulnerability.setAliases(computeAliases(vulnerability, qm, problems));
            }
            final JSONArray cvssArray = vulnAttributes.optJSONArray("severities");
            vulnerability = cvssArray != null ? setCvssScore(cvssArray, vulnerability) : vulnerability;
            JSONArray coordinates = vulnAttributes.optJSONArray("coordinates");
            if (coordinates != null) {

                for (int countCoordinates = 0; countCoordinates < coordinates.length(); countCoordinates++) {
                    JSONArray representation = coordinates.getJSONObject(countCoordinates).optJSONArray("representation");
                    if ((representation.length() == 1 && representation.get(0).equals("*"))) {
                        LOGGER.debug("Range only contains *. Will not compute vulnerable software for this range. Purl is: "+purl);
                    } else {
                        vsList = parseVersionRanges(qm, purl, representation);
                    }

                    JSONArray remedies = coordinates.getJSONObject(countCoordinates).optJSONArray("remedies");
                    if (remedies != null) {
                        var recommendation = "";
                        for (int remedyCount = 0; remedyCount < remedies.length(); remedyCount++) {
                            var remedy = remedies.getJSONObject(remedyCount).optString("description");
                            recommendation += remedy + System.lineSeparator();
                        }
                        vulnerability.setRecommendation(recommendation);
                    }
                }
            }
            final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(vulnerability.getSource(), vulnerability.getVulnId()));
            synchronizedVulnerability = qm.synchronizeVulnerability(vulnerability, false);
            qm.persist(vsList);
            qm.updateAffectedVersionAttributions(synchronizedVulnerability, vsList, Vulnerability.Source.SNYK);
            vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.SNYK);
            synchronizedVulnerability.setVulnerableSoftware(vsList);
            qm.persist(synchronizedVulnerability);
        }
        return synchronizedVulnerability;
    }

    public List<SnykError> parseErrors(final JSONObject jsonResponse) {
        if (jsonResponse == null) {
            return Collections.emptyList();
        }

        final JSONArray errorsArray = jsonResponse.optJSONArray("errors");
        if (errorsArray == null) {
            return Collections.emptyList();
        }

        final var errors = new ArrayList<SnykError>();
        for (int i = 0; i < errorsArray.length(); i++) {
            final JSONObject errorObject = errorsArray.optJSONObject(i);
            if (errorObject == null) {
                continue;
            }

            errors.add(new SnykError(
                    errorObject.optString("code"),
                    errorObject.optString("title"),
                    errorObject.optString("detail")
            ));
        }

        return errors;
    }

    public List<VulnerabilityAlias> computeAliases(Vulnerability vulnerability, QueryManager qm, JSONArray problems) {
        List<VulnerabilityAlias> vulnerabilityAliasList = new ArrayList<>();
        for (int i = 0; i < problems.length(); i++) {
            final JSONObject problem = problems.optJSONObject(i);
            String source = problem.optString("source");
            String id = problem.optString("id");
            // CWE
            if (source.equalsIgnoreCase("CWE")) {
                final Cwe cwe = CweResolver.getInstance().resolve(qm, id);
                if (cwe != null) {
                    vulnerability.addCwe(cwe);
                }
            }
            // CVE alias
            else if (source.equalsIgnoreCase("CVE")) {
                final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();
                vulnerabilityAlias.setSnykId(vulnerability.getVulnId());
                vulnerabilityAlias.setCveId(id);
                qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                vulnerabilityAliasList.add(vulnerabilityAlias);
            }
            // Github alias
            else if (source.equalsIgnoreCase("GHSA")) {
                final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();
                vulnerabilityAlias.setSnykId(vulnerability.getVulnId());
                vulnerabilityAlias.setGhsaId(id);
                qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                vulnerabilityAliasList.add(vulnerabilityAlias);
            }
        }
        return vulnerabilityAliasList;
    }

    public Vulnerability setCvssScore(JSONArray cvssArray, Vulnerability vulnerability) {
        JSONObject cvss = selectCvssObjectBasedOnSource(cvssArray);
        if (cvss != null) {
            String severity = cvss.optString("level", null);
            if (severity != null) {
                if (severity.equalsIgnoreCase("CRITICAL")) {
                    vulnerability.setSeverity(Severity.CRITICAL);
                } else if (severity.equalsIgnoreCase("HIGH")) {
                    vulnerability.setSeverity(Severity.HIGH);
                } else if (severity.equalsIgnoreCase("MEDIUM")) {
                    vulnerability.setSeverity(Severity.MEDIUM);
                } else if (severity.equalsIgnoreCase("LOW")) {
                    vulnerability.setSeverity(Severity.LOW);
                } else {
                    vulnerability.setSeverity(Severity.UNASSIGNED);
                }
            }
            vulnerability.setCvssV3Vector(cvss.optString("vector", null));
            final String cvssScore = cvss.optString("score");
            if (cvssScore != null) {
                vulnerability.setCvssV3BaseScore(BigDecimal.valueOf(Double.parseDouble(cvssScore)));
            }
        }
        return vulnerability;
    }

    public String addReferences(JSONObject slots) {
        final JSONArray links = slots.optJSONArray("references");
        final StringBuilder sb = new StringBuilder();
        for (int linkCount = 0; linkCount < links.length(); linkCount++) {
            final JSONObject link = links.getJSONObject(linkCount);
            String reference = link.optString("url", null);
            if (reference != null) {
                sb.append("* [").append(reference).append("](").append(reference).append(")\n");
            }
        }
        return sb.toString();
    }

    public JSONObject selectCvssObjectBasedOnSource(JSONArray cvssArray) {

        String cvssSourceHigh = getSnykCvssConfig(ConfigPropertyConstants.SCANNER_SNYK_CVSS_SOURCE);
        String cvssSourceLow = cvssSourceHigh.equalsIgnoreCase(SnykCvssSource.NVD.toString()) ? SnykCvssSource.SNYK.toString() : SnykCvssSource.NVD.toString();
        JSONObject cvss = cvssArray.optJSONObject(0);
        if (cvssArray.length() > 1) {
            for (int i = 0; i < cvssArray.length(); i++) {
                final JSONObject cvssObject = cvssArray.optJSONObject(i);
                String source = cvssObject.optString("source");
                String vector = cvssObject.optString("vector");
                String score = cvssObject.optString("score");
                if (!source.isBlank() && !vector.isBlank() && !score.isBlank()) {
                    if (source.equalsIgnoreCase(cvssSourceHigh)) {
                        return cvssObject;
                    }
                    if (source.equalsIgnoreCase(cvssSourceLow)) {
                        cvss = cvssObject;
                    } else {
                        if (cvss != null && !cvss.optString("source").equalsIgnoreCase(cvssSourceLow)) {
                            cvss = cvssObject;
                        }
                    }
                }
            }
        }
        return cvss;
    }

    public List<VulnerableSoftware> parseVersionRanges(final QueryManager qm, final String purl, final JSONArray ranges) {

        List<VulnerableSoftware> vulnerableSoftwares = new ArrayList<>();
        if (purl == null) {
            LOGGER.debug("No PURL provided - skipping");
            return Collections.emptyList();
        }

        final PackageURL packageURL;
        try {
            packageURL = new PackageURL(purl);
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Invalid PURL  " + purl + " - skipping", ex);
            return Collections.emptyList();
        }
        for (int i = 0; i < ranges.length(); i++) {

            String range = ranges.optString(i);
            String versionStartIncluding = null;
            String versionStartExcluding = null;
            String versionEndIncluding = null;
            String versionEndExcluding = null;

            final String[] parts;

            if (range.contains(",")) {
                parts = Arrays.stream(range.split(",")).map(String::trim).toArray(String[]::new);
            } else {
                parts = Arrays.stream(range.split(" ")).map(String::trim).toArray(String[]::new);
            }
            for (String part : parts) {
                if (part.startsWith(">=") || part.startsWith("[")) {
                    versionStartIncluding = part.replace(">=", "").replace("[", "").trim();
                    if (versionStartIncluding.length() == 0 || versionStartIncluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else if (part.startsWith(">") || part.startsWith("(")) {
                    versionStartExcluding = part.replace(">", "").replace("(", "").trim();
                    if (versionStartExcluding.length() == 0 || versionStartExcluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else if (part.startsWith("<=") || part.endsWith("]")) {
                    versionEndIncluding = part.replace("<=", "").replace("]", "").trim();
                } else if (part.startsWith("<") || part.endsWith(")")) {
                    versionEndExcluding = part.replace("<", "").replace(")", "").trim();
                    if (versionEndExcluding.length() == 0 || versionEndExcluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else if (part.startsWith("=")) {
                    versionStartIncluding = part.replace("=", "").trim();
                    versionEndIncluding = part.replace("=", "").trim();
                    if (versionStartIncluding.length() == 0 || versionStartIncluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                    if (versionEndIncluding.length() == 0 || versionEndIncluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else { //since we are not able to parse specific range, we do not want to end up with false positives and therefore this part will be skipped from being saved to db.
                    LOGGER.debug("Range not definite. Not saving this vulnerable software information. The purl was: "+purl);
                }
            }
            
            //check for a numeric definite version range
            if ((versionStartIncluding != null && versionEndIncluding != null) || (versionStartIncluding != null && versionEndExcluding != null) || (versionStartExcluding != null && versionEndIncluding != null) || (versionStartExcluding != null && versionEndExcluding != null)) {
                VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(packageURL.getType(), packageURL.getNamespace(), packageURL.getName(), versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
                if (vs == null) {
                    vs = new VulnerableSoftware();
                    vs.setVulnerable(true);
                    vs.setPurlType(packageURL.getType());
                    vs.setPurlNamespace(packageURL.getNamespace());
                    vs.setPurlName(packageURL.getName());
                    vs.setVersion(packageURL.getVersion());
                    vs.setVersionStartIncluding(versionStartIncluding);
                    vs.setVersionStartExcluding(versionStartExcluding);
                    vs.setVersionEndIncluding(versionEndIncluding);
                    vs.setVersionEndExcluding(versionEndExcluding);
                }
                vulnerableSoftwares.add(vs);
            } else {
                LOGGER.debug("Range not definite. Not saving this vulnerable software information. The purl was: "+purl);
            }
        }
        return vulnerableSoftwares;
    }

    public String getSnykCvssConfig(ConfigPropertyConstants scannerSnykCvssSource) {

        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(scannerSnykCvssSource.getGroupName(), scannerSnykCvssSource.getPropertyName());
            if (property != null && ConfigProperty.PropertyType.STRING == property.getPropertyType()) {
                return property.getPropertyValue();
            }
        }
        return scannerSnykCvssSource.getDefaultPropertyValue();
    }
}
