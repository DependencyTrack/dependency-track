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
package org.dependencytrack.parser.osv;

import org.json.JSONArray;
import org.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Severity;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

/*
    Parser for Google OSV, an aggregator of vulnerability databases including GitHub Security Advisories, PyPA, RustSec, and Global Security Database, and more.
 */
public class OsvAdvisoryParser {

    public OsvAdvisory parse(final JSONObject object) {

        OsvAdvisory advisory = null;

        // initial check if advisory is valid or withdrawn
        String withdrawn = object.optString("withdrawn", null);

        if(object != null && withdrawn == null) {

            advisory = new OsvAdvisory();
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

            final List<OsvAffectedPackage> affectedPackages = parseAffectedPackages(object);
            advisory.setAffectedPackages(affectedPackages);
        }
        return advisory;
    }

    private List<OsvAffectedPackage> parseAffectedPackages(final JSONObject advisory) {

        List<OsvAffectedPackage> affectedPackages = new ArrayList<>();
        final JSONArray affected = advisory.optJSONArray("affected");
        if (affected != null) {
            for(int i=0; i<affected.length(); i++) {

                affectedPackages.addAll(parseAffectedPackageRange(affected.getJSONObject(i)));
            }
        }
        return affectedPackages;
    }

    public List<OsvAffectedPackage> parseAffectedPackageRange(final JSONObject affected) {

        List<OsvAffectedPackage> osvAffectedPackageList = new ArrayList<>();
        final JSONArray ranges = affected.optJSONArray("ranges");
        final JSONArray versions = affected.optJSONArray("versions");
        if (ranges != null) {
            for (int j=0; j<ranges.length(); j++) {
                final JSONObject range = ranges.getJSONObject(j);
                osvAffectedPackageList.addAll(parseVersionRanges(affected, range));
            }
        }
        // if ranges are not available or only commit hash range is available, look for versions
        if (osvAffectedPackageList.size() == 0 && versions != null && versions.length() > 0) {
            for (int j=0; j<versions.length(); j++) {
                OsvAffectedPackage vuln = createAffectedPackage(affected);
                vuln.setVersion(versions.getString(j));
                osvAffectedPackageList.add(vuln);
            }
        }
        // if no parsable range or version is available, add vulnerability without version
        else if (osvAffectedPackageList.size() == 0) {
            osvAffectedPackageList.add(createAffectedPackage(affected));
        }
        return osvAffectedPackageList;
    }

    private List<OsvAffectedPackage> parseVersionRanges(JSONObject vulnerability, JSONObject range) {
        final String rangeType = range.optString("type");
        if (!"ECOSYSTEM".equalsIgnoreCase(rangeType) && !"SEMVER".equalsIgnoreCase(rangeType)) {
            // We can't support ranges of type GIT for now, as evaluating them requires knowledge of
            // the entire Git history of a package. We don't have that, so there's no point in
            // ingesting this data.
            //
            // We're also implicitly excluding ranges of types that we don't yet know of.
            // This is a tradeoff of potentially missing new data vs. flooding our users'
            // database with junk data.
            return List.of();
        }

        final JSONArray rangeEvents = range.optJSONArray("events");
        if (rangeEvents == null) {
            return List.of();
        }

        final List<OsvAffectedPackage> affectedPackages = new ArrayList<>();

        for (int i = 0; i < rangeEvents.length(); i++) {
            JSONObject event = rangeEvents.getJSONObject(i);

            final String introduced = event.optString("introduced", null);
            if (introduced == null) {
                // "introduced" is required for every range. But events are not guaranteed to be sorted,
                // it's merely a recommendation by the OSV specification.
                //
                // If events are not sorted, we have no way to tell what the correct order should be.
                // We make a tradeoff by assuming that ranges are sorted, and potentially skip ranges
                // that aren't.
                continue;
            }

            final OsvAffectedPackage affectedPackage = createAffectedPackage(vulnerability);
            affectedPackage.setLowerVersionRange(introduced);

            if (i + 1 < rangeEvents.length()) {
                event = rangeEvents.getJSONObject(i + 1);
                final String fixed = event.optString("fixed", null);
                final String lastAffected = event.optString("last_affected", null);
                final String limit = event.optString("limit", null);

                if (fixed != null) {
                    affectedPackage.setUpperVersionRangeExcluding(fixed);
                    i++;
                } else if (lastAffected != null) {
                    affectedPackage.setUpperVersionRangeIncluding(lastAffected);
                    i++;
                } else if (limit != null) {
                    affectedPackage.setUpperVersionRangeExcluding(limit);
                    i++;
                }
            }

            // Special treatment for GitHub: https://github.com/github/advisory-database/issues/470
            final JSONObject databaseSpecific = vulnerability.optJSONObject("database_specific");
            if (databaseSpecific != null
                    && affectedPackage.getUpperVersionRangeIncluding() == null
                    && affectedPackage.getUpperVersionRangeExcluding() == null) {
                final String lastAffectedRange = databaseSpecific.optString("last_known_affected_version_range", null);
                if (lastAffectedRange != null) {
                    if (lastAffectedRange.startsWith("<=")) {
                        affectedPackage.setUpperVersionRangeIncluding(lastAffectedRange.replaceFirst("<=", "").trim());
                    } else if (lastAffectedRange.startsWith("<")) {
                        affectedPackage.setUpperVersionRangeExcluding(lastAffectedRange.replaceAll("<", "").trim());
                    }
                }
            }

            affectedPackages.add(affectedPackage);
        }

        return affectedPackages;
    }

    private OsvAffectedPackage createAffectedPackage(JSONObject vulnerability) {

        OsvAffectedPackage osvAffectedPackage = new OsvAffectedPackage();
        final JSONObject affectedPackageJson = vulnerability.optJSONObject("package");
        final JSONObject ecosystemSpecific = vulnerability.optJSONObject("ecosystem_specific");
        final JSONObject databaseSpecific = vulnerability.optJSONObject("database_specific");
        Severity ecosystemSeverity = parseEcosystemSeverity(ecosystemSpecific, databaseSpecific);
        osvAffectedPackage.setPackageName(affectedPackageJson.optString("name", null));
        osvAffectedPackage.setPackageEcosystem(affectedPackageJson.optString("ecosystem", null));
        osvAffectedPackage.setPurl(affectedPackageJson.optString("purl", null));
        osvAffectedPackage.setSeverity(ecosystemSeverity);
        return osvAffectedPackage;
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