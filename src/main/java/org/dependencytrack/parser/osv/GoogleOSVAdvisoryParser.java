package org.dependencytrack.parser.osv;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.parser.osv.model.OSVVulnerability;

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

            final JSONArray vulnerabilities = object.optJSONArray("affected");
            if (vulnerabilities != null) {
                for(int i=0; i<vulnerabilities.length(); i++) {

                    OSVVulnerability osvVulnerability = new OSVVulnerability();
                    final JSONObject vulnerability = vulnerabilities.getJSONObject(i);
                    final JSONObject affectedPackageJson = vulnerability.optJSONObject("package");
                    osvVulnerability.setPackageName(affectedPackageJson.optString("name", null));
                    osvVulnerability.setPackageEcosystem(affectedPackageJson.optString("ecosystem", null));
                    osvVulnerability.setPurl(affectedPackageJson.optString("purl", null));

                    final JSONArray versions = vulnerability.optJSONArray("versions");
                    if (versions != null) {
                        for (int j=0; j<versions.length(); j++) {
                            osvVulnerability.addVersion(versions.optString(j));
                        }
                    }
                    // TODO 1. set version ranges TBD
                    // final JSONArray ranges = vulnerability.optJSONArray("ranges");
                    advisory.addVulnerability(osvVulnerability);
                }
            }
        }
        return advisory;
    }
}