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
package org.dependencytrack.parser.github.graphql;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.parser.github.graphql.model.GitHubSecurityAdvisory;
import org.dependencytrack.parser.github.graphql.model.GitHubVulnerability;
import org.dependencytrack.parser.github.graphql.model.PageableList;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

public class GitHubSecurityAdvisoryParser {

    public PageableList parse(final JSONObject object) {
        final PageableList pageableList = new PageableList();
        final List<GitHubSecurityAdvisory> advisories = new ArrayList<>();
        final JSONObject data = object.optJSONObject("data");
        if (data != null) {
            final JSONObject securityAdvisories = data.getJSONObject("securityAdvisories");
            if (securityAdvisories != null) {
                final JSONArray securityAdvisoriesNodes = securityAdvisories.getJSONArray("nodes");
                if (securityAdvisoriesNodes != null) {
                    for (int i = 0; i < securityAdvisoriesNodes.length(); i++) {
                        final JSONObject securityAdvisory = securityAdvisoriesNodes.getJSONObject(i);
                        final GitHubSecurityAdvisory advisory = parseSecurityAdvisory(securityAdvisory);
                        advisories.add(advisory);
                    }
                }
                pageableList.setTotalCount(securityAdvisories.optInt("totalCount"));
                final JSONObject pageInfo = securityAdvisories.getJSONObject("pageInfo");
                if (pageInfo != null) {
                    pageableList.setHasNextPage(pageInfo.optBoolean("hasNextPage"));
                    pageableList.setHasPreviousPage(pageInfo.optBoolean("hasPreviousPage"));
                    pageableList.setStartCursor(pageInfo.optString("startCursor"));
                    pageableList.setEndCursor(pageInfo.optString("endCursor"));
                }
            }
        }
        pageableList.setAdvisories(advisories);
        return pageableList;
    }

    private GitHubSecurityAdvisory parseSecurityAdvisory(final JSONObject object) {
        final GitHubSecurityAdvisory advisory = new GitHubSecurityAdvisory();
        advisory.setDatabaseId(object.getInt("databaseId"));
        advisory.setDescription(object.optString("description", null));
        advisory.setGhsaId(object.optString("ghsaId", null));
        advisory.setId(object.optString("id", null));
        advisory.setNotificationsPermalink(object.optString("notificationsPermalink", null));
        advisory.setOrigin(object.optString("origin", null));
        advisory.setPermalink(object.optString("permalink", null));
        advisory.setSeverity(object.optString("severity", null));
        advisory.setSummary(object.optString("summary", null));
        advisory.setPublishedAt(jsonStringToTimestamp(object.optString("publishedAt", null)));
        advisory.setUpdatedAt(jsonStringToTimestamp(object.optString("updatedAt", null)));
        advisory.setWithdrawnAt(jsonStringToTimestamp(object.optString("withdrawnAt", null)));

        final JSONArray identifiers = object.optJSONArray("identifiers");
        if (identifiers != null) {
            for (int i=0; i<identifiers.length(); i++) {
                final JSONObject identifier = identifiers.getJSONObject(i);
                final String type = identifier.optString("type", null);
                final String value = identifier.optString("value", null);
                if (type != null && value != null) {
                    final Pair<String, String> pair = Pair.of(type, value);
                    advisory.addIdentifier(pair);
                }
            }
        }

        final JSONArray references = object.optJSONArray("references");
        if (references != null) {
            for (int i=0; i<references.length(); i++) {
                final String url = references.optJSONObject(i).optString("url", null);
                if (url != null) {
                    advisory.addReference(url);
                }
            }
        }

        final JSONObject cvss = object.optJSONObject("cvss");
        if (cvss != null) {
            advisory.setCvssScore(cvss.optInt("score", 0));
            advisory.setCvssVector(cvss.optString("vectorString", null));
        }

        final JSONObject cwes = object.optJSONObject("cwes");
        if (cwes != null) {
            final JSONArray edges = cwes.optJSONArray("edges");
            if (edges != null) {
                for (int i = 0; i < edges.length(); i++) {
                    final JSONObject edge = edges.optJSONObject(i);
                    if (edge != null) {
                        final JSONObject node = edge.optJSONObject("node");
                        if (node != null) {
                            final String cweId = node.optString("cweId", null);
                            if (cweId != null) {
                                advisory.addCwe(cweId);
                            }
                        }
                    }
                }
            }
        }
        final List<GitHubVulnerability> vulnerabilities = parseVulnerabilities(object);
        advisory.setVulnerabilities(vulnerabilities);
        return advisory;
    }

    private List<GitHubVulnerability> parseVulnerabilities(final JSONObject object) {
        final List<GitHubVulnerability> vulnerabilities = new ArrayList<>();
        final JSONObject vs = object.optJSONObject("vulnerabilities");
        if (vs != null) {
            final JSONArray edges = vs.optJSONArray("edges");
            if (edges != null) {
                for (int i=0; i<edges.length(); i++) {
                    final JSONObject node = edges.getJSONObject(i).optJSONObject("node");
                    if (node != null) {
                        GitHubVulnerability vulnerability = parseVulnerability(node);
                        vulnerabilities.add(vulnerability);
                    }
                }
            }
        }
        return vulnerabilities;
    }

    private GitHubVulnerability parseVulnerability(final JSONObject object) {
        final GitHubVulnerability vulnerability = new GitHubVulnerability();
        vulnerability.setSeverity(object.optString("severity", null));
        vulnerability.setUpdatedAt(jsonStringToTimestamp(object.optString("updatedAt", null)));
        final JSONObject firstPatchedVersion = object.optJSONObject("firstPatchedVersion");
        if (firstPatchedVersion != null) {
            vulnerability.setFirstPatchedVersionIdentifier(firstPatchedVersion.optString("identifier", null));
        }
        vulnerability.setVulnerableVersionRange(object.optString("vulnerableVersionRange", null));
        final JSONObject packageObject = object.optJSONObject("package");
        if (packageObject != null) {
            vulnerability.setPackageEcosystem(packageObject.optString("ecosystem", null));
            vulnerability.setPackageName(packageObject.optString("name", null));
        }
        return vulnerability;
    }

    private ZonedDateTime jsonStringToTimestamp(final String s) {
        if (s == null) {
            return null;
        }
        try {
            return ZonedDateTime.parse(s);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
