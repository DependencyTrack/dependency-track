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
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.persistence.QueryManager;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.Score;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigDecimal;

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
                final JsonObject meta0 = cveItem.getJsonObject("CVE_data_meta");
                final JsonString meta1 = meta0.getJsonString("CVE_ID");
                vulnerability.setVulnId(meta1.getString());

                // CVE Description
                final JsonObject descO = cveItem.getJsonObject("CVE_description");
                final JsonArray desc1 = descO.getJsonArray("CVE_description_data");
                for (int j = 0; j < desc1.size(); j++) {
                    final JsonObject desc2 = desc1.getJsonObject(j);
                    if ("en".equals(desc2.getString("lang"))) {
                        vulnerability.setDescription(desc2.getString("value"));
                    }
                }

                // CVE Impact
                parseCveImpact(cveItem, vulnerability);

                // CWE
                final JsonObject prob0 = cveItem.getJsonObject("CVE_problemtype");
                final JsonArray prob1 = prob0.getJsonArray("CVE_problemtype_data");
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
                qm.synchronizeVulnerability(vulnerability, false);
            }
        } catch (Exception e) {
            LOGGER.error("Error parsing NVD JSON data");
            LOGGER.error(e.getMessage());
        }
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private void parseCveImpact(JsonObject cveItem, Vulnerability vulnerability) {
        final JsonObject imp0 = cveItem.getJsonObject("CVE_impact");
        final JsonObject imp1 = imp0.getJsonObject("CVE_impact_cvssv2");
        if (imp1 != null) {
            final JsonObject imp2 = imp1.getJsonObject("bm");
            if (imp2 != null) {
                final String av = normalize(imp2.getJsonString("av"));
                final String ac = normalize(imp2.getJsonString("ac"));
                final String au = normalize(imp2.getJsonString("au"));
                final String c = normalize(imp2.getJsonString("c"));
                final String i = normalize(imp2.getJsonString("i"));
                final String a = normalize(imp2.getJsonString("a"));
                //final JsonString score = imp2.getJsonString("score");

                if (av != null && ac != null && au != null && c != null && i != null && a != null) {
                    final CvssV2 cvssV2 = new CvssV2()
                            .attackVector(CvssV2.AttackVector.valueOf(av))
                            .attackComplexity(CvssV2.AttackComplexity.valueOf(ac))
                            .authentication(CvssV2.Authentication.valueOf(au))
                            .confidentiality(CvssV2.CIA.valueOf(c))
                            .integrity(CvssV2.CIA.valueOf(i))
                            .availability(CvssV2.CIA.valueOf(a));

                    final Score score = cvssV2.calculateScore();
                    vulnerability.setCvssV2Vector(cvssV2.getVector());
                    vulnerability.setCvssV2BaseScore(new BigDecimal(score.getBaseScore()));
                    vulnerability.setCvssV2ExploitabilitySubScore(new BigDecimal(score.getExploitabilitySubScore()));
                    vulnerability.setCvssV2ImpactSubScore(new BigDecimal(score.getImpactSubScore()));
                }
            }
        }
        final JsonObject imp3 = imp0.getJsonObject("CVE_impact_cvssv3");
        if (imp3 != null) {
            final JsonObject imp4 = imp3.getJsonObject("bm");
            if (imp4 != null) {
                final String av = normalize(imp4.getJsonString("av"));
                final String ac = normalize(imp4.getJsonString("ac"));
                final String pr = normalize(imp4.getJsonString("pr"));
                final String ui = normalize(imp4.getJsonString("ui"));
                final String s = normalize(imp4.getJsonString("scope"));
                final String c = normalize(imp4.getJsonString("c"));
                final String i = normalize(imp4.getJsonString("i"));
                final String a = normalize(imp4.getJsonString("a"));
                //final JsonString score = imp4.getJsonString("score");

                if (av != null && ac != null && pr != null && ui != null && s != null && c != null && i != null && a != null) {
                    final CvssV3 cvssV3 = new CvssV3()
                            .attackVector(CvssV3.AttackVector.valueOf(av))
                            .attackComplexity(CvssV3.AttackComplexity.valueOf(ac))
                            .privilegesRequired(CvssV3.PrivilegesRequired.valueOf(pr))
                            .userInteraction(CvssV3.UserInteraction.valueOf(ui))
                            .scope(CvssV3.Scope.valueOf(s))
                            .confidentiality(CvssV3.CIA.valueOf(c))
                            .integrity(CvssV3.CIA.valueOf(i))
                            .availability(CvssV3.CIA.valueOf(a));

                    final Score score = cvssV3.calculateScore();
                    vulnerability.setCvssV3Vector(cvssV3.getVector());
                    vulnerability.setCvssV3BaseScore(new BigDecimal(score.getBaseScore()));
                    vulnerability.setCvssV3ExploitabilitySubScore(new BigDecimal(score.getExploitabilitySubScore()));
                    vulnerability.setCvssV3ImpactSubScore(new BigDecimal(score.getImpactSubScore()));
                }
            }
        }
    }

    private String normalize(JsonString in) {
        switch (in.getString()) {
            case ("SINGLE")             : return "SINGLE";
            case ("SINGLE_INSTANCE")    : return "SINGLE";
            case ("MULTIPLE_INSTANCES") : return "MULTIPLE";
            case ("NONE")               : return "NONE";
            case ("LOW")                : return "LOW";
            case ("MEDIUM")             : return "MEDIUM";
            case ("HIGH")               : return "HIGH";
            case ("PARTIAL")            : return "PARTIAL";
            case ("COMPLETE")           : return "COMPLETE";
            case ("LOCAL")              : return "LOCAL";
            case ("ADJACENT")           : return "ADJACENT";
            case ("LOCAL_NETWORK")      : return "ADJACENT";
            case ("NETWORK")            : return "NETWORK";
            case ("PHYSICAL")           : return "PHYSICAL";
            case ("REQUIRED")           : return "REQUIRED";
            case ("UNCHANGED")          : return "UNCHANGED";
            case ("CHANGED")            : return "CHANGED";
            default                     : return null;
        }
    }

}
