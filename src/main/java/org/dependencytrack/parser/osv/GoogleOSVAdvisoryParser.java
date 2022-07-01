package org.dependencytrack.parser.osv;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
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
        final JSONArray versions = vulnerability.optJSONArray("versions");
        if (ranges != null) {
            for (int j=0; j<ranges.length(); j++) {
                final JSONObject range = ranges.getJSONObject(j);
                String rangeType = range.optString("type", null);
                if(rangeType != null && !rangeType.equalsIgnoreCase("GIT")) {
                    osvVulnerabilityList.addAll(parseVersionRanges(vulnerability, range));
                }
            }
        }
        // if ranges are not available or only commit hash range is available, look for versions
        if (osvVulnerabilityList.size() == 0 && versions != null && versions.length() > 0) {
            for (int j=0; j<versions.length(); j++) {
                OSVVulnerability vuln = createOSVVulnerability(vulnerability);
                vuln.setVersion(versions.getString(j));
                osvVulnerabilityList.add(vuln);
            }
        }
        // if no parsable range or version is avilable, add vulnerability without version
        else if (osvVulnerabilityList.size() == 0) {
            osvVulnerabilityList.add(createOSVVulnerability(vulnerability));
        }
        return osvVulnerabilityList;
    }

    private List<OSVVulnerability> parseVersionRanges(JSONObject vulnerability, JSONObject range) {

        final List<OSVVulnerability> osvVulnerabilityList = new ArrayList<>();
        final JSONArray rangeEvents = range.optJSONArray("events");
        final JSONObject databaseSpecific = vulnerability.optJSONObject("database_specific");
        if(rangeEvents != null) {
            int k = 0;
            while (k < rangeEvents.length()) {

                OSVVulnerability osvVulnerability = createOSVVulnerability(vulnerability);
                JSONObject event = rangeEvents.getJSONObject(k);
                String lower = event.optString("introduced", null);
                if(lower != null) {
                    osvVulnerability.setLowerVersionRange(lower);
                    k += 1;
                }
                if(k < rangeEvents.length()) {
                    event = rangeEvents.getJSONObject(k);
                    String fixed = event.optString("fixed", null);
                    String lastAffected = event.optString("last_affected", null);
                    String limit = event.optString("limit", null);
                    if (fixed != null) {
                        osvVulnerability.setUpperVersionRangeExcluding(fixed);
                        k += 1;
                    } else if (lastAffected != null){
                        osvVulnerability.setUpperVersionRangeIncluding(lastAffected);
                        k += 1;
                    } else if (limit != null) {
                        osvVulnerability.setUpperVersionRangeExcluding(limit);
                        k += 1;
                    }
                }
                if (osvVulnerability.getUpperVersionRangeIncluding() == null
                        && osvVulnerability.getUpperVersionRangeExcluding() == null
                        && databaseSpecific != null) {
                    String lastAffected = databaseSpecific.optString("last_known_affected_version_range", null);
                    if (lastAffected != null) {
                        osvVulnerability.setUpperVersionRangeIncluding(lastAffected.replaceAll("[^0-9.]+", "").trim());
                    }
                }
                osvVulnerabilityList.add(osvVulnerability);
            }
        }
        return osvVulnerabilityList;
    }

    private OSVVulnerability createOSVVulnerability(JSONObject vulnerability) {

        OSVVulnerability osvVulnerability = new OSVVulnerability();
        final JSONObject affectedPackageJson = vulnerability.optJSONObject("package");
        final JSONObject ecosystemSpecific = vulnerability.optJSONObject("ecosystem_specific");
        final JSONObject databaseSpecific = vulnerability.optJSONObject("database_specific");
        Severity ecosystemSeverity = parseEcosystemSeverity(ecosystemSpecific, databaseSpecific);
        osvVulnerability.setPackageName(affectedPackageJson.optString("name", null));
        osvVulnerability.setPackageEcosystem(affectedPackageJson.optString("ecosystem", null));
        osvVulnerability.setPurl(affectedPackageJson.optString("purl", null));
        osvVulnerability.setSeverity(ecosystemSeverity);
        return osvVulnerability;
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
        if(summary != null && summary.length() > 255) {
            return StringUtils.substring(summary, 0, MAX_LEN-2) + "..";
        }
        return summary;
    }
}