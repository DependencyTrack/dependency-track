/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.npm.audit;

import alpine.logging.Logger;
import io.github.openunirest.http.JsonNode;
import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.parser.npm.audit.model.Advisory;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for NPM Audit API response.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
public class NpmAuditParser {

    private static final Logger LOGGER = Logger.getLogger(NpmAuditParser.class);

    /**
     * Parses the JSON response from the NPM Audit API.
     *
     * @param jsonNode the JSON node to parse
     * @return an AdvisoryResults object
     */
    public List<Advisory> parse(JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");
        List<Advisory> advisories = new ArrayList<>();
        JSONObject jsonAdvisories = jsonNode.getObject().getJSONObject("advisories");
        for (String key : jsonAdvisories.keySet()) {
            Advisory advisory = parse(jsonAdvisories.getJSONObject(key));
            advisories.add(advisory);
        }
        return advisories;
    }

    private Advisory parse(JSONObject object) {
        final Advisory advisory = new Advisory();
        advisory.setId(object.getInt("id"));
        advisory.setOverview(object.optString("overview", null));
        advisory.setReferences(object.optString("references", null));
        advisory.setCreated(object.optString("created", null));
        advisory.setUpdated(object.optString("updated", null));
        advisory.setRecommendation(object.optString("recommendation", null));
        advisory.setTitle(object.optString("title", null));
        //advisory.setFoundBy(object.optString("author", null));
        //advisory.setReportedBy(object.optString("author", null));
        advisory.setModuleName(object.optString("module_name", null));
        advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
        advisory.setPatchedVersions(object.optString("patched_versions", null));
        advisory.setAccess(object.optString("access", null));
        advisory.setSeverity(object.optString("severity", null));
        advisory.setCwe(object.optString("cwe", null));

        final JSONArray findings = object.optJSONArray("findings");
        for (int i = 0; i < findings.length(); i++) {
            final JSONObject finding = findings.getJSONObject(i);
            final String version = finding.optString("version", null);
            JSONArray paths = finding.optJSONArray("paths");
            for (int j = 0; j < paths.length(); j++) {
                final String path = paths.getString(i);
                if (path != null && path.equals(advisory.getModuleName())) {
                    advisory.setVersion(version);
                }
            }
        }

        final JSONArray jsonCves = object.optJSONArray("cves");
        final List<String> stringCves = new ArrayList<>();
        if (jsonCves != null) {
            for (int j = 0; j < jsonCves.length(); j++) {
                stringCves.add(jsonCves.getString(j));
            }
            advisory.setCves(stringCves.toArray(new String[stringCves.size()]));
        }
        return advisory;
    }
}
