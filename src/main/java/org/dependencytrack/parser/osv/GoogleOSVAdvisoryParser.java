package org.dependencytrack.parser.osv;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Severity;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.parser.osv.model.OSVVulnerability;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

/*
    Parser for Google OSV, an aggregator of vulnerability databases including GitHub Security Advisories, PyPA, RustSec, and Global Security Database, and more.
 */
public class GoogleOSVAdvisoryParser {

    public OSVAdvisory parse(final JSONObject object) {

        OSVAdvisory advisory = null;

        // initial check if advisory is valid or withdrawn
        String withdrawn = object.optString("withdrawn", null);

        if(object != null && withdrawn == null) {

            advisory = new OSVAdvisory();
            advisory.setId(object.optString("id", null));
            advisory.setSummary(trimSummary(object.optString("summary", null)));
            advisory.setDetails(object.optString("details", null));
            advisory.setPublished(jsonStringToTimestamp(object.optString("published", null)));
            advisory.setModified(jsonStringToTimestamp(object.optString("modified", null)));
            advisory.setSchema_version(object.optString("schema_version", null));

            final JSONArray references = object.optJSONArray("references");
            if (references != null) {
                for (int i=0; i<references.length(); i++) {
                    final JSONObject reference = references.getJSONObject(i);
                    final String url = reference.optString("url", null);
                    advisory.addReference(url);
                }
            }

            final JSONArray credits = object.optJSONArray("credits");
            if (credits != null) {
                for (int i=0; i<credits.length(); i++) {
                    final JSONObject credit = credits.getJSONObject(i);
                    final String name = credit.optString("name", null);
                    advisory.addCredit(name);
                }
            }

            final JSONArray aliases = object.optJSONArray("aliases");
            if(aliases != null) {
                for (int i=0; i<aliases.length(); i++) {
                    advisory.addAlias(aliases.optString(i));
                }
            }

            final JSONObject databaseSpecific = object.optJSONObject("database_specific");
            if (databaseSpecific != null) {
                advisory.setSeverity(databaseSpecific.optString("severity", null));
                final JSONArray cweIds = databaseSpecific.optJSONArray("cwe_ids");
                if(cweIds != null) {
                    for (int i=0; i<cweIds.length(); i++) {
                        advisory.addCweId(cweIds.optString(i));
                    }
                }
            }

            final JSONArray cvssList = object.optJSONArray("severity");
            if (cvssList != null) {
                for (int i=0; i<cvssList.length(); i++) {
                    final JSONObject cvss = cvssList.getJSONObject(i);
                    final String type = cvss.optString("type", null);
                    if (type.equalsIgnoreCase("CVSS_V3")) {
                        advisory.setCvssV3Vector(cvss.optString("score", null));
                    }
                    if (type.equalsIgnoreCase("CVSS_V2")) {
                        advisory.setCvssV2Vector(cvss.optString("score", null));
                    }
                }
            }

            final List<OSVVulnerability> vulnerabilities = parseVulnerabilities(object);
            advisory.setVulnerabilities(vulnerabilities);
        }
        return advisory;
    }

    private List<OSVVulnerability> parseVulnerabilities(JSONObject object) {

        List<OSVVulnerability> osvVulnerabilityList = new ArrayList<>();
        final JSONArray vulnerabilities = object.optJSONArray("affected");
        if (vulnerabilities != null) {
            for(int i=0; i<vulnerabilities.length(); i++) {
                osvVulnerabilityList.addAll(parseVulnerabilityRange(vulnerabilities.getJSONObject(i)));
            }
        }
        return osvVulnerabilityList;
    }

    public List<OSVVulnerability> parseVulnerabilityRange(JSONObject vulnerability) {

        List<OSVVulnerability> osvVulnerabilityList = new ArrayList<>();
        final JSONArray ranges = vulnerability.optJSONArray("ranges");

        if (ranges != null) {
            for (int j=0; j<ranges.length(); j++) {
                final JSONObject range = ranges.getJSONObject(j);
                osvVulnerabilityList.addAll(parseVersionRanges(vulnerability, range));
            }
        }
        return osvVulnerabilityList;
    }

    private List<OSVVulnerability> parseVersionRanges(JSONObject vulnerability, JSONObject range) {

        final JSONObject affectedPackageJson = vulnerability.optJSONObject("package");
        final JSONObject ecosystemSpecific = vulnerability.optJSONObject("ecosystem_specific");
        final JSONObject databaseSpecific = vulnerability.optJSONObject("database_specific");
        Severity ecosystemSeverity = parseEcosystemSeverity(ecosystemSpecific, databaseSpecific);

        final List<OSVVulnerability> osvVulnerabilityList = new ArrayList<>();
        final JSONArray rangeEvents = range.optJSONArray("events");
        if(rangeEvents != null) {
            int k = 0;
            while (k < rangeEvents.length()) {

                OSVVulnerability osvVulnerability = new OSVVulnerability();
                osvVulnerability.setPackageName(affectedPackageJson.optString("name", null));
                osvVulnerability.setPackageEcosystem(affectedPackageJson.optString("ecosystem", null));
                osvVulnerability.setPurl(affectedPackageJson.optString("purl", null));
                osvVulnerability.setSeverity(ecosystemSeverity);

                JSONObject event = rangeEvents.getJSONObject(k);
                String lower = event.optString("introduced", null);
                if(lower != null) {
                    osvVulnerability.setLowerVersionRange(lower);
                    k += 1;
                }
                if(k < rangeEvents.length()) {
                    event = rangeEvents.getJSONObject(k);
                    String upper = event.optString("fixed", null);
                    if(upper != null) {
                        osvVulnerability.setUpperVersionRange(upper);
                        k += 1;
                    }
                }
                osvVulnerabilityList.add(osvVulnerability);
            }
        }
        return osvVulnerabilityList;
    }

    private Severity parseEcosystemSeverity(JSONObject ecosystemSpecific, JSONObject databaseSpecific) {

        String severity = null;

        if (databaseSpecific != null) {
            String cvssVector = databaseSpecific.optString("cvss", null);
            if (cvssVector != null) {
                Cvss cvss = Cvss.fromVector(cvssVector);
                Score score = cvss.calculateScore();
                severity = String.valueOf(normalizedCvssV3Score(score.getBaseScore()));
            }
        }

        if(severity == null && ecosystemSpecific != null) {
            severity = ecosystemSpecific.optString("severity", null);
        }

        if (severity != null) {
            if (severity.equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (severity.equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (severity.equalsIgnoreCase("MODERATE") || severity.equalsIgnoreCase("MEDIUM")) {
                return Severity.MEDIUM;
            } else if (severity.equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            }
        }
        return Severity.UNASSIGNED;
    }

    public String trimSummary(String summary) {

        final int MAX_LEN = 255;
        // NPE safe
        return StringUtils.substring(summary, 0, MAX_LEN-2) + "..";
    }
}