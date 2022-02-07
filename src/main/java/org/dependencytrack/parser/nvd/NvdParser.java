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
package org.dependencytrack.parser.nvd;

import alpine.event.framework.Event;
import alpine.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import us.springett.cvss.Cvss;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.Part;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.sql.Date;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser and processor of NVD data feeds.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class NvdParser {

    private static final Logger LOGGER = Logger.getLogger(NvdParser.class);
    private enum Operator {
        AND,
        OR,
        NONE
    }

    public void parse(final File file) {
        if (!file.getName().endsWith(".json")) {
            return;
        }

        LOGGER.info("Parsing " + file.getName());

        try (InputStream in = Files.newInputStream(file.toPath());
             final JsonReader reader = Json.createReader(in)) {

            final JsonObject root = reader.readObject();
            final JsonArray cveItems = root.getJsonArray("CVE_Items");

            cveItems.forEach((c) -> {
                final JsonObject cveItem = (JsonObject) c;
                try (QueryManager qm = new QueryManager()) {
                    final Vulnerability vulnerability = new Vulnerability();
                    vulnerability.setSource(Vulnerability.Source.NVD);

                    // CVE ID
                    final JsonObject cve = cveItem.getJsonObject("cve");
                    final JsonObject meta0 = cve.getJsonObject("CVE_data_meta");
                    final JsonString meta1 = meta0.getJsonString("ID");
                    vulnerability.setVulnId(meta1.getString());

                    // CVE Published and Modified dates
                    final String publishedDateString = cveItem.getString("publishedDate");
                    final String lastModifiedDateString = cveItem.getString("lastModifiedDate");
                    try {
                        if (StringUtils.isNotBlank(publishedDateString)) {
                            vulnerability.setPublished(Date.from(OffsetDateTime.parse(publishedDateString).toInstant()));
                        }
                        if (StringUtils.isNotBlank(lastModifiedDateString)) {
                            vulnerability.setUpdated(Date.from(OffsetDateTime.parse(lastModifiedDateString).toInstant()));
                        }
                    } catch (DateTimeParseException | NullPointerException | IllegalArgumentException e) {
                        LOGGER.error("Unable to parse dates from NVD data feed", e);
                    }

                    // CVE Description
                    final JsonObject descO = cve.getJsonObject("description");
                    final JsonArray desc1 = descO.getJsonArray("description_data");
                    final StringBuilder descriptionBuilder = new StringBuilder();
                    for (int j = 0; j < desc1.size(); j++) {
                        final JsonObject desc2 = desc1.getJsonObject(j);
                        if ("en".equals(desc2.getString("lang"))) {
                            descriptionBuilder.append(desc2.getString("value"));
                            if (j < desc1.size() - 1) {
                                descriptionBuilder.append("\n\n");
                            }
                        }
                    }
                    vulnerability.setDescription(descriptionBuilder.toString());

                    // CVE Impact
                    parseCveImpact(cveItem, vulnerability);

                    // CWE
                    final JsonObject prob0 = cve.getJsonObject("problemtype");
                    final JsonArray prob1 = prob0.getJsonArray("problemtype_data");
                    for (int j = 0; j < prob1.size(); j++) {
                        final JsonObject prob2 = prob1.getJsonObject(j);
                        final JsonArray prob3 = prob2.getJsonArray("description");
                        for (int k = 0; k < prob3.size(); k++) {
                            final JsonObject prob4 = prob3.getJsonObject(k);
                            if ("en".equals(prob4.getString("lang"))) {
                                final String cweString = prob4.getString("value");
                                if (cweString != null && cweString.startsWith("CWE-")) {
                                    try {
                                        final int cweId = Integer.parseInt(cweString.substring(4).trim());
                                        final Cwe cwe = qm.getCweById(cweId);
                                        vulnerability.setCwe(cwe);
                                    } catch (NumberFormatException e) {
                                        // throw it away
                                    }
                                }
                            }
                        }
                    }

                    // References
                    final JsonObject ref0 = cve.getJsonObject("references");
                    final JsonArray ref1 = ref0.getJsonArray("reference_data");
                    final StringBuilder sb = new StringBuilder();
                    for (int l = 0; l < ref1.size(); l++) {
                        final JsonObject ref2 = ref1.getJsonObject(l);
                        for (final String s : ref2.keySet()) {
                            if ("url".equals(s)) {
                                // Convert reference to Markdown format
                                final String url = ref2.getString("url");
                                sb.append("* [").append(url).append("](").append(url).append(")\n");
                            }
                        }
                    }
                    final String references = sb.toString();
                    if (references.length() > 0) {
                        vulnerability.setReferences(references.substring(0, references.lastIndexOf("\n")));
                    }

                    // Update the vulnerability
                    LOGGER.debug("Synchronizing: " + vulnerability.getVulnId());
                    final Vulnerability synchronizeVulnerability = qm.synchronizeVulnerability(vulnerability, false);

                    // CPE
                    final List<VulnerableSoftware> vulnerableSoftwares = new ArrayList<>();
                    final JsonObject configurations = cveItem.getJsonObject("configurations");
                    final JsonArray nodes = configurations.getJsonArray("nodes");
                    for (int j = 0; j < nodes.size(); j++) {
                        final JsonObject node = nodes.getJsonObject(j);
                        final List<VulnerableSoftware> vulnerableSoftwareInNode = new ArrayList<>();
                        final Operator nodeOperator = Operator.valueOf(node.getString("operator", Operator.NONE.name()));
                        if (node.containsKey("children")) {
                            // https://github.com/DependencyTrack/dependency-track/issues/1033
                            final JsonArray children = node.getJsonArray("children");
                            if (children.size() > 0) {
                                for (int l = 0; l < children.size(); l++) {
                                    final JsonObject child = children.getJsonObject(l);
                                    vulnerableSoftwareInNode.addAll(parseCpes(qm, child, synchronizeVulnerability));
                                }
                            } else {
                                vulnerableSoftwareInNode.addAll(parseCpes(qm, node, synchronizeVulnerability));
                            }
                        } else {
                            vulnerableSoftwareInNode.addAll(parseCpes(qm, node, synchronizeVulnerability));
                        }
                        vulnerableSoftwares.addAll(reconcile(vulnerableSoftwareInNode, nodeOperator));
                        qm.persist(vulnerableSoftwares);
                    }
                    synchronizeVulnerability.setVulnerableSoftware(vulnerableSoftwares);
                    qm.persist(synchronizeVulnerability);
                }
            });
        } catch (Exception e) {
            LOGGER.error("An error occurred while parsing NVD JSON data", e);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Cpe.class));
    }

    /**
     * CVE configurations may consist of applications and operating systems. In the case of
     * configurations that contain both application and operating system parts, we do not
     * want both types of CPEs to be associated to the vulnerability as it will lead to
     * false positives on the operating system. https://nvd.nist.gov/vuln/detail/CVE-2015-0312
     * is a good example of this as it contains application CPEs describing various versions
     * of Adobe Flash player, but also contains CPEs for all versions of Windows, macOS, and
     * Linux. This method will only return a List of VulnerableSoftware objects which are
     * applications when there are also operating system CPE in list supplied to this method.
     * @param vulnerableSoftwareList a list of all VulnerableSoftware object for a given CVE
     * @return a reconciled list of VulnerableSoftware objects
     */
    private List<VulnerableSoftware> reconcile(List<VulnerableSoftware> vulnerableSoftwareList, final Operator nodeOperator) {
        final List<VulnerableSoftware> appPartList = new ArrayList<>();
        final List<VulnerableSoftware> osPartList = new ArrayList<>();
        if (Operator.AND == nodeOperator) {
            for (VulnerableSoftware vulnerableSoftware: vulnerableSoftwareList) {
                if (vulnerableSoftware.getCpe23() != null && Part.OPERATING_SYSTEM.getAbbreviation().equals(vulnerableSoftware.getPart())) {
                    osPartList.add(vulnerableSoftware);
                }
                if (vulnerableSoftware.getCpe23() != null && Part.APPLICATION.getAbbreviation().equals(vulnerableSoftware.getPart())) {
                    appPartList.add(vulnerableSoftware);
                }
            }
            if (!osPartList.isEmpty() && !appPartList.isEmpty()) {
                return appPartList;
            } else {
                return vulnerableSoftwareList;
            }
        }
        return vulnerableSoftwareList;
    }

    private void parseCveImpact(final JsonObject cveItem, final Vulnerability vuln) {
        final JsonObject imp0 = cveItem.getJsonObject("impact");
        final JsonObject imp1 = imp0.getJsonObject("baseMetricV2");
        if (imp1 != null) {
            final JsonObject imp2 = imp1.getJsonObject("cvssV2");
            if (imp2 != null) {
                final Cvss cvss = Cvss.fromVector(imp2.getJsonString("vectorString").getString());
                vuln.setCvssV2Vector(cvss.getVector()); // normalize the vector but use the scores from the feed
                vuln.setCvssV2BaseScore(imp2.getJsonNumber("baseScore").bigDecimalValue());
            }
            vuln.setCvssV2ExploitabilitySubScore(imp1.getJsonNumber("exploitabilityScore").bigDecimalValue());
            vuln.setCvssV2ImpactSubScore(imp1.getJsonNumber("impactScore").bigDecimalValue());
        }

        final JsonObject imp3 = imp0.getJsonObject("baseMetricV3");
        if (imp3 != null) {
            final JsonObject imp4 = imp3.getJsonObject("cvssV3");
            if (imp4 != null) {
                final Cvss cvss = Cvss.fromVector(imp4.getJsonString("vectorString").getString());
                vuln.setCvssV3Vector(cvss.getVector()); // normalize the vector but use the scores from the feed
                vuln.setCvssV3BaseScore(imp4.getJsonNumber("baseScore").bigDecimalValue());
            }
            vuln.setCvssV3ExploitabilitySubScore(imp3.getJsonNumber("exploitabilityScore").bigDecimalValue());
            vuln.setCvssV3ImpactSubScore(imp3.getJsonNumber("impactScore").bigDecimalValue());
        }
    }

    private List<VulnerableSoftware> parseCpes(final QueryManager qm, final JsonObject node, final Vulnerability vulnerability) {
        final List<VulnerableSoftware> vsList = new ArrayList<>();
        if (node.containsKey("cpe_match")) {
            final JsonArray cpeMatches = node.getJsonArray("cpe_match");
            for (int k = 0; k < cpeMatches.size(); k++) {
                final JsonObject cpeMatch = cpeMatches.getJsonObject(k);
                if (cpeMatch.getBoolean("vulnerable", true)) { // only parse the CPEs marked as vulnerable
                    final VulnerableSoftware vs = generateVulnerableSoftware(qm, cpeMatch, vulnerability);
                    if (vs != null) {
                        vsList.add(vs);
                    }
                }
            }
        }
        return vsList;
    }

    private VulnerableSoftware generateVulnerableSoftware(final QueryManager qm, final JsonObject cpeMatch,
                                                                       final Vulnerability vulnerability) {
        final String cpe23Uri = cpeMatch.getString("cpe23Uri");
        final String versionEndExcluding = cpeMatch.getString("versionEndExcluding", null);
        final String versionEndIncluding = cpeMatch.getString("versionEndIncluding", null);
        final String versionStartExcluding = cpeMatch.getString("versionStartExcluding", null);
        final String versionStartIncluding = cpeMatch.getString("versionStartIncluding", null);
        VulnerableSoftware vs = qm.getVulnerableSoftwareByCpe23(cpe23Uri, versionEndExcluding,
                versionEndIncluding, versionStartExcluding, versionStartIncluding);
        if (vs != null) {
            return vs;
        }
        try {
            vs = ModelConverter.convertCpe23UriToVulnerableSoftware(cpe23Uri);
            vs.setVulnerable(cpeMatch.getBoolean("vulnerable", true));
            vs.setVersionEndExcluding(versionEndExcluding);
            vs.setVersionEndIncluding(versionEndIncluding);
            vs.setVersionStartExcluding(versionStartExcluding);
            vs.setVersionStartIncluding(versionStartIncluding);
            //Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, qm.detach(VulnerableSoftware.class, vs.getId())));
            return vs;
        } catch (CpeParsingException | CpeEncodingException e) {
            LOGGER.warn("An error occurred while parsing: " + cpe23Uri + " - The CPE is invalid and will be discarded.");
        }
        return null;
    }
}
