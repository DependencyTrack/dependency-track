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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.composer;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.parser.composer.model.ComposerSecurityVulnerability;
import org.json.JSONArray;
import org.json.JSONObject;

import alpine.common.logging.Logger;


public class ComposerSecurityAdvisoryParser {

    private static final Logger LOGGER = Logger.getLogger(ComposerSecurityAdvisoryParser.class);

    public List<ComposerSecurityVulnerability> parse(final JSONObject object) {
        final List<ComposerSecurityVulnerability> result = new ArrayList<>();
        final JSONObject advisories = object.optJSONObject("advisories");
        if (advisories != null) {
            advisories.names().forEach(packageName -> {
                final JSONArray advisory = advisories.optJSONArray((String)packageName);
                if (advisory != null) {
                    for (int i = 0; i < advisory.length(); i++) {
                        final ComposerSecurityVulnerability composerVulnerability = parseSecurityAdvisory(advisory.getJSONObject(i));
                        if (composerVulnerability != null) {
                            result.add(composerVulnerability);
                        }
                    }

                }
            });
        }
        return result;
    }

    private ComposerSecurityVulnerability parseSecurityAdvisory(final JSONObject object) {
        final ComposerSecurityVulnerability advisory = new ComposerSecurityVulnerability();

        //There's no status field in the advisory object, so we cannot check if the advisory has been withdrawn
        advisory.setAdvisoryId(object.getString("advisoryId"));
        advisory.setPackageName(object.optString("packageName", null));
        advisory.setRemoteId(object.optString("remoteId", null));
        advisory.setTitle(object.optString("title", null));
        advisory.setLink(object.optString("link", null));
        advisory.setCve(object.optString("cve", null));
        advisory.setAffectedVersionsCve(object.optString("affectedVersions", null));
        advisory.setSource(object.optString("source", null));

        String reportedAtStr = object.optString("reportedAt", null);
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            if (reportedAtStr != null) {
                LocalDateTime reportedAt = LocalDateTime.parse(reportedAtStr, formatter);
                advisory.setReportedAt(reportedAt);
            }
        } catch (DateTimeParseException e) {
            LOGGER.debug("Unabled to parse as LocalDateTime: " + reportedAtStr);
        }

        advisory.setComposerRepository(object.optString("composerRepository", null));
        advisory.setSeverity(object.optString("severity", null));

        //Some repositories like drupal use something weird as name that might not be unique
        final JSONArray identifiers = object.optJSONArray("sources");
        if (identifiers != null) {
            for (int i = 0; i < identifiers.length(); i++) {
                final JSONObject identifier = identifiers.getJSONObject(i);
                final String type = identifier.optString("name", null);
                final String value = identifier.optString("remoteId", null);
                if (type != null && value != null) {
                    final Pair<String, String> pair = Pair.of(type, value);
                    advisory.addSource(pair);
                }
            }
        }

        return advisory;
    }

}
