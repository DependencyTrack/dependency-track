package org.dependencytrack.parser.osv;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.parser.osv.model.OSVVulnerability;

import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;

/*
    Parser for Google OSV, an aggregator of vulnerability databases including GitHub Security Advisories, PyPA, RustSec, and Global Security Database, and more.
 */
public class GoogleOSVAdvisoryParser {

    public OSVAdvisory parse(final JSONObject object) {

        final OSVAdvisory advisory = new OSVAdvisory();
        if(object != null) {
            advisory.setId(object.optString("id", null));
            advisory.setSummary(object.optString("summary", null));
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

            final JSONObject cvss = object.optJSONObject("severity");
            if (cvss != null) {
                advisory.setCvssVector(cvss.optString("vectorString", null));
                // TODO: add cvss score calculation if required
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

                final JSONObject vulnerability = vulnerabilities.getJSONObject(i);
                final JSONObject affectedPackageJson = vulnerability.optJSONObject("package");
                final JSONArray ranges = vulnerability.optJSONArray("ranges");

                if (ranges != null) {
                    for (int j=0; j<ranges.length(); j++) {
                        final JSONObject range = ranges.getJSONObject(i);
                        if(range.optString("type").equalsIgnoreCase("ECOSYSTEM")){
                            osvVulnerabilityList = parseVersionRanges(affectedPackageJson, range);
                        }

                    }
                }
            }
        }
        return osvVulnerabilityList;
    }

    private List<OSVVulnerability> parseVersionRanges(JSONObject affectedPackageJson, JSONObject range) {

        final List<OSVVulnerability> osvVulnerabilityList = new ArrayList<>();
        final JSONArray rangeEvents = range.optJSONArray("events");
        if(rangeEvents != null) {
            int k = 0;
            while (k < rangeEvents.length()) {

                OSVVulnerability osvVulnerability = new OSVVulnerability();
                osvVulnerability.setPackageName(affectedPackageJson.optString("name", null));
                osvVulnerability.setPackageEcosystem(affectedPackageJson.optString("ecosystem", null));
                osvVulnerability.setPurl(affectedPackageJson.optString("purl", null));

                JSONObject event = rangeEvents.getJSONObject(k);
                String lower = event.optString("introduced", null);
                if(lower != null) {
                    osvVulnerability.setLowerVersionRange(lower);
                    k += 1;
                }
                event = rangeEvents.getJSONObject(k);
                String upper = event.optString("fixed", null);
                if(upper != null) {
                    osvVulnerability.setUpperVersionRange(upper);
                    k += 1;
                }
                osvVulnerabilityList.add(osvVulnerability);
            }
        }
        return osvVulnerabilityList;
    }
}