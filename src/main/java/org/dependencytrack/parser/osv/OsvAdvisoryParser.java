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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.Json;
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

    public OsvAdvisory parse(final JsonNode object) {

        OsvAdvisory advisory = null;

        // initial check if advisory is valid or withdrawn
        String withdrawn = Json.optString(object, "withdrawn", null);

        if (object != null && withdrawn == null) {

            advisory = new OsvAdvisory();
            advisory.setId(Json.optString(object, "id", null));
            advisory.setSummary(trimSummary(Json.optString(object, "summary", null)));
            advisory.setDetails(Json.optString(object, "details", null));
            advisory.setPublished(jsonStringToTimestamp(Json.optString(object, "published", null)));
            advisory.setModified(jsonStringToTimestamp(Json.optString(object, "modified", null)));
            advisory.setSchema_version(Json.optString(object, "schema_version", null));

            final ArrayNode references = Json.optArray(object, "references");
            if (references != null) {
                for (int i = 0; i < references.size(); i++) {
                    final JsonNode reference = references.get(i);
                    final String url = Json.optString(reference, "url", null);
                    if (url != null) {
                        advisory.addReference(url);
                    }
                }
            }

            final ArrayNode credits = Json.optArray(object, "credits");
            if (credits != null) {
                for (int i = 0; i < credits.size(); i++) {
                    final JsonNode credit = credits.get(i);
                    final String name = Json.optString(credit, "name", null);
                    if (name != null) {
                        advisory.addCredit(name);
                    }
                }
            }

            final ArrayNode aliases = Json.optArray(object, "aliases");
            if (aliases != null) {
                for (int i = 0; i < aliases.size(); i++) {
                    final String alias = Json.optString(aliases, i, null);
                    if (alias != null) {
                        advisory.addAlias(Json.optString(aliases, i));
                    }
                }
            }

            final JsonNode databaseSpecific = object.get("database_specific");
            if (databaseSpecific != null) {
                advisory.setSeverity(Json.optString(databaseSpecific, "severity", null));
                final ArrayNode cweIds = Json.optArray(databaseSpecific, "cwe_ids");
                if (cweIds != null) {
                    for (int i = 0; i < cweIds.size(); i++) {
                        advisory.addCweId(Json.optString(cweIds, i));
                    }
                }
            }

            final ArrayNode cvssList = Json.optArray(object, "severity");
            if (cvssList != null) {
                for (int i = 0; i < cvssList.size(); i++) {
                    final JsonNode cvss = cvssList.get(i);
                    final String type = Json.optString(cvss, "type");
                    if (type.equalsIgnoreCase("CVSS_V3")) {
                        advisory.setCvssV3Vector(Json.optString(cvss, "score", null));
                    }
                    if (type.equalsIgnoreCase("CVSS_V2")) {
                        advisory.setCvssV2Vector(Json.optString(cvss, "score", null));
                    }
                }
            }

            final List<OsvAffectedPackage> affectedPackages = parseAffectedPackages(object);
            advisory.setAffectedPackages(affectedPackages);
        }
        return advisory;
    }

    private List<OsvAffectedPackage> parseAffectedPackages(final JsonNode advisory) {

        List<OsvAffectedPackage> affectedPackages = new ArrayList<>();
        final ArrayNode affected = Json.optArray(advisory, "affected");
        if (affected != null) {
            for (int i = 0; i < affected.size(); i++) {

                affectedPackages.addAll(parseAffectedPackageRange(affected.get(i)));
            }
        }
        return affectedPackages;
    }

    public List<OsvAffectedPackage> parseAffectedPackageRange(final JsonNode affected) {

        List<OsvAffectedPackage> osvAffectedPackageList = new ArrayList<>();
        final ArrayNode ranges = Json.optArray(affected, "ranges");
        final ArrayNode versions = Json.optArray(affected, "versions");
        if (ranges != null) {
            for (int j = 0; j < ranges.size(); j++) {
                final JsonNode range = ranges.get(j);
                osvAffectedPackageList.addAll(parseVersionRanges(affected, range));
            }
        }
        // if ranges are not available or only commit hash range is available, look for versions
        if (osvAffectedPackageList.size() == 0 && versions != null && versions.size() > 0) {
            for (int j = 0; j < versions.size(); j++) {
                OsvAffectedPackage vuln = createAffectedPackage(affected);
                vuln.setVersion(versions.get(j).asText());
                osvAffectedPackageList.add(vuln);
            }
        }
        // if no parsable range or version is available, add vulnerability without version
        else if (osvAffectedPackageList.size() == 0) {
            osvAffectedPackageList.add(createAffectedPackage(affected));
        }
        return osvAffectedPackageList;
    }

    private List<OsvAffectedPackage> parseVersionRanges(JsonNode vulnerability, JsonNode range) {
        final String rangeType = Json.optString(range, "type");
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

        final ArrayNode rangeEvents = Json.optArray(range, "events");
        if (rangeEvents == null) {
            return List.of();
        }

        final List<OsvAffectedPackage> affectedPackages = new ArrayList<>();

        for (int i = 0; i < rangeEvents.size(); i++) {
            JsonNode event = rangeEvents.get(i);

            final String introduced = Json.optString(event, "introduced", null);
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

            if (i + 1 < rangeEvents.size()) {
                event = rangeEvents.get(i + 1);
                final String fixed = Json.optString(event, "fixed", null);
                final String lastAffected = Json.optString(event, "last_affected", null);
                final String limit = Json.optString(event, "limit", null);

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
            final JsonNode databaseSpecific = vulnerability.get("database_specific");
            if (databaseSpecific != null
                    && affectedPackage.getUpperVersionRangeIncluding() == null
                    && affectedPackage.getUpperVersionRangeExcluding() == null) {
                final String lastAffectedRange = Json.optString(databaseSpecific, "last_known_affected_version_range", null);
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

    private OsvAffectedPackage createAffectedPackage(JsonNode vulnerability) {

        OsvAffectedPackage osvAffectedPackage = new OsvAffectedPackage();
        final JsonNode affectedPackageJson = vulnerability.get("package");
        final JsonNode ecosystemSpecific = vulnerability.get("ecosystem_specific");
        final JsonNode databaseSpecific = vulnerability.get("database_specific");
        Severity ecosystemSeverity = parseEcosystemSeverity(ecosystemSpecific, databaseSpecific);
        osvAffectedPackage.setPackageName(Json.optString(affectedPackageJson, "name", null));
        osvAffectedPackage.setPackageEcosystem(Json.optString(affectedPackageJson, "ecosystem", null));
        osvAffectedPackage.setPurl(Json.optString(affectedPackageJson, "purl", null));
        osvAffectedPackage.setSeverity(ecosystemSeverity);
        return osvAffectedPackage;
    }

    private Severity parseEcosystemSeverity(JsonNode ecosystemSpecific, JsonNode databaseSpecific) {

        String severity = null;

        if (databaseSpecific != null) {
            String cvssVector = Json.optString(databaseSpecific, "cvss", null);
            if (cvssVector != null) {
                Cvss cvss = Cvss.fromVector(cvssVector);
                Score score = cvss.calculateScore();
                severity = String.valueOf(normalizedCvssV3Score(score.getBaseScore()));
            }
        }

        if (severity == null && ecosystemSpecific != null) {
            severity = Json.optString(ecosystemSpecific, "severity", null);
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
        if (summary != null && summary.length() > 255) {
            return StringUtils.substring(summary, 0, MAX_LEN - 2) + "..";
        }
        return summary;
    }
}