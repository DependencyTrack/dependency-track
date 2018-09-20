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
package org.dependencytrack.parser.npm;

import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.parser.npm.model.Advisory;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for NPM Advisory objects common to NPM Audit and NPM Advisory APIs.
 *
 * @author Steve Springett
 * @since 3.2.1
 */
public abstract class BaseAdvisoryParser {

    protected Advisory parse(JSONObject object) {
        final Advisory advisory = new Advisory();
        advisory.setId(object.getInt("id"));
        advisory.setOverview(object.optString("overview", null));
        advisory.setReferences(object.optString("references", null));
        advisory.setCreated(object.optString("created", null));
        advisory.setUpdated(object.optString("updated", null));
        advisory.setRecommendation(object.optString("recommendation", null));
        advisory.setTitle(object.optString("title", null));
        advisory.setModuleName(object.optString("module_name", null));
        advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
        advisory.setPatchedVersions(object.optString("patched_versions", null));
        advisory.setAccess(object.optString("access", null));
        advisory.setSeverity(object.optString("severity", null));
        advisory.setCwe(object.optString("cwe", null));

        final JSONObject foundBy = object.optJSONObject("found_by");
        if (foundBy != null) {
            advisory.setFoundBy(foundBy.optString("name", null));
        }

        final JSONObject reportedBy = object.optJSONObject("reported_by");
        if (reportedBy != null) {
            advisory.setReportedBy(reportedBy.optString("name", null));
        }

        // Findings are only relevant to the NPM Audit API and will not be present in the NPM Advisory API
        final JSONArray findings = object.optJSONArray("findings");
        if (findings != null) {
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
