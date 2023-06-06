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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.common.Json;
import org.dependencytrack.parser.github.graphql.model.GitHubSecurityAdvisory;
import org.dependencytrack.parser.github.graphql.model.GitHubVulnerability;
import org.dependencytrack.parser.github.graphql.model.PageableList;

import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;

public class GitHubSecurityAdvisoryParser {

    public PageableList parse(final JsonNode object) {
        final PageableList pageableList = new PageableList();
        final List<GitHubSecurityAdvisory> advisories = new ArrayList<>();
        final JsonNode data = object.get("data");
        if (data != null) {
            final JsonNode securityAdvisories = data.get("securityAdvisories");
            if (securityAdvisories != null) {
                final ArrayNode securityAdvisoriesNodes = Json.optArray(securityAdvisories, "nodes");
                if (securityAdvisoriesNodes != null) {
                    for (int i = 0; i < securityAdvisoriesNodes.size(); i++) {
                        final JsonNode securityAdvisory = securityAdvisoriesNodes.get(i);
                        final GitHubSecurityAdvisory advisory = parseSecurityAdvisory(securityAdvisory);
                        advisories.add(advisory);
                    }
                }
                pageableList.setTotalCount(Json.optInt(securityAdvisories,"totalCount"));
                final JsonNode pageInfo = securityAdvisories.get("pageInfo");
                if (pageInfo != null) {
                    pageableList.setHasNextPage(Json.optBoolean(pageInfo,"hasNextPage"));
                    pageableList.setHasPreviousPage(Json.optBoolean(pageInfo,"hasPreviousPage"));
                    pageableList.setStartCursor(Json.optString(pageInfo,"startCursor"));
                    pageableList.setEndCursor(Json.optString(pageInfo,"endCursor"));
                }
            }
        }
        pageableList.setAdvisories(advisories);
        return pageableList;
    }

    private GitHubSecurityAdvisory parseSecurityAdvisory(final JsonNode object) {
        final GitHubSecurityAdvisory advisory = new GitHubSecurityAdvisory();
        advisory.setDatabaseId(Json.optInt(object, "databaseId"));
        advisory.setDescription(Json.optString(object,"description", null));
        advisory.setGhsaId(Json.optString(object,"ghsaId", null));
        advisory.setId(Json.optString(object,"id", null));
        advisory.setNotificationsPermalink(Json.optString(object,"notificationsPermalink", null));
        advisory.setOrigin(Json.optString(object,"origin", null));
        advisory.setPermalink(Json.optString(object,"permalink", null));
        advisory.setSeverity(Json.optString(object,"severity", null));
        advisory.setSummary(Json.optString(object,"summary", null));
        advisory.setPublishedAt(jsonStringToTimestamp(Json.optString(object,"publishedAt", null)));
        advisory.setUpdatedAt(jsonStringToTimestamp(Json.optString(object,"updatedAt", null)));
        advisory.setWithdrawnAt(jsonStringToTimestamp(Json.optString(object,"withdrawnAt", null)));

        final ArrayNode identifiers = Json.optArray(object,"identifiers");
        if (identifiers != null) {
            for (int i=0; i<identifiers.size(); i++) {
                final JsonNode identifier = identifiers.get(i);
                final String type = Json.optString(identifier,"type", null);
                final String value = Json.optString(identifier,"value", null);
                if (type != null && value != null) {
                    final Pair<String, String> pair = Pair.of(type, value);
                    advisory.addIdentifier(pair);
                }
            }
        }

        final ArrayNode references = Json.optArray(object,"references");
        if (references != null) {
            for (int i=0; i<references.size(); i++) {
                final String url = Json.optString(references.get(i), "url", null);
                if (url != null) {
                    advisory.addReference(url);
                }
            }
        }

        final JsonNode cvss = object.get("cvss");
        if (cvss != null) {
            advisory.setCvssScore(Json.optInt(cvss, "score"));
            advisory.setCvssVector(Json.optString(cvss,"score", null));
        }

        final JsonNode cwes = object.get("cwes");
        if (cwes != null) {
            final ArrayNode edges = Json.optArray(cwes,"edges");
            if (edges != null) {
                for (int i = 0; i < edges.size(); i++) {
                    final JsonNode edge = edges.get(i);
                    if (edge != null) {
                        final JsonNode node = edge.get("node");
                        if (node != null) {
                            final String cweId = Json.optString(node,"cweId", null);
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

    private List<GitHubVulnerability> parseVulnerabilities(final JsonNode object) {
        final List<GitHubVulnerability> vulnerabilities = new ArrayList<>();
        final JsonNode vs = object.get("vulnerabilities");
        if (vs != null) {
            final ArrayNode edges = Json.optArray(vs,"edges");
            if (edges != null) {
                for (int i=0; i<edges.size(); i++) {
                    final JsonNode node = edges.get(i).get("node");
                    if (node != null) {
                        GitHubVulnerability vulnerability = parseVulnerability(node);
                        vulnerabilities.add(vulnerability);
                    }
                }
            }
        }
        return vulnerabilities;
    }

    private GitHubVulnerability parseVulnerability(final JsonNode object) {
        final GitHubVulnerability vulnerability = new GitHubVulnerability();
        vulnerability.setSeverity(Json.optString(object,"severity", null));
        vulnerability.setUpdatedAt(jsonStringToTimestamp(Json.optString(object,"updatedAt", null)));
        final JsonNode firstPatchedVersion = object.get("firstPatchedVersion");
        if (firstPatchedVersion != null) {
            vulnerability.setFirstPatchedVersionIdentifier(Json.optString(firstPatchedVersion,"identifier", null));
        }
        vulnerability.setVulnerableVersionRange(Json.optString(object,"vulnerableVersionRange", null));
        final JsonNode packageObject = object.get("package");
        if (packageObject != null) {
            vulnerability.setPackageEcosystem(Json.optString(packageObject,"ecosystem", null));
            vulnerability.setPackageName(Json.optString(packageObject,"name", null));
        }
        return vulnerability;
    }
}
