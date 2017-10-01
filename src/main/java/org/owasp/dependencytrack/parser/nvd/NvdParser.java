/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.parser.nvd;

import alpine.event.framework.SingleThreadedEventService;
import alpine.logging.Logger;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.persistence.QueryManager;
import us.springett.cvss.Cvss;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.sql.Date;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

/**
 * Parser and processor of NVD data feeds.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class NvdParser {

    private static final Logger LOGGER = Logger.getLogger(NvdParser.class);

    public void parse(File file) {
        if (!file.getName().endsWith(".json")) {
            return;
        }

        LOGGER.info("Parsing " + file.getName());

        try (QueryManager qm = new QueryManager()) {

            final InputStream in = new FileInputStream(file);
            final JsonReader reader = Json.createReader(in);

            final JsonObject root = reader.readObject();
            final JsonArray cveItems = root.getJsonArray("CVE_Items");
            for (int i = 0; i < cveItems.size(); i++) {
                final Vulnerability vulnerability = new Vulnerability();
                vulnerability.setSource(Vulnerability.Source.NVD);

                final JsonObject cveItem = cveItems.getJsonObject(i);

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
                for (int j = 0; j < desc1.size(); j++) {
                    final JsonObject desc2 = desc1.getJsonObject(j);
                    if ("en".equals(desc2.getString("lang"))) {
                        vulnerability.setDescription(desc2.getString("value"));
                    }
                }

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
                            //vulnerability.setCwe(prob4.getString("value"));
                            final String cweString = prob4.getString("value");
                            if (cweString != null && cweString.startsWith("CWE-")) {
                                try {
                                    final int cweId = Integer.parseInt(cweString.substring(4, cweString.length()).trim());
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
                    for (String s : ref2.keySet()) {
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
                qm.synchronizeVulnerability(vulnerability, false);
            }
        } catch (Exception e) {
            LOGGER.error("Error parsing NVD JSON data");
            LOGGER.error(e.getMessage());
        }
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private void parseCveImpact(JsonObject cveItem, Vulnerability vuln) {
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

}
