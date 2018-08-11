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
package org.dependencytrack.parser.nsp;

import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.parser.nsp.model.Advisory;
import java.util.ArrayList;
import java.util.List;

public class BaseAdvisoryParser {

    public Advisory parse(JSONObject object) {
        final Advisory advisory = new Advisory();
        advisory.setId(object.getInt("id"));
        advisory.setOverview(object.optString("overview", null));
        advisory.setCvssScore(object.optDouble("cvss_score", 0.0));
        advisory.setCvssVector(object.optString("cvss_vector", null));
        advisory.setReferences(object.optString("references", null));
        advisory.setAuthor(object.optString("author", null));
        advisory.setCreatedAt(object.optString("created_at", null));
        advisory.setUpdatedAt(object.optString("updated_at", null));
        advisory.setRecommendation(object.optString("recommendation", null));
        advisory.setTitle(object.optString("title", null));

        /*
        'module_name' is used in the advisories api
        'module' is used in the check api
        try one, then the other
         */
        advisory.setModuleName(object.optString("module_name", null));
        if (advisory.getModuleName() == null) {
            advisory.setModuleName(object.optString("module", null));
        }

        advisory.setModuleName(object.optString("module", null));
        advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
        advisory.setPatchedVersions(object.optString("patched_versions", null));
        advisory.setVersion(object.optString("version", null));
        advisory.setPublishDate(object.optString("publish_date", null));
        advisory.setSlug(object.optString("slug", null));
        advisory.setLegacySlug(object.optString("legacy_slug", null));

        // The 'path' is only available when calling the 'check' api
        JSONArray path = object.optJSONArray("path");
        if (path != null && path.length() > 0) {
            List<String> paths = new ArrayList<>();
            for (int i = 0; i < path.length(); i++) {
                paths.add(path.getString(i));
            }
            advisory.setPath(paths);
        }

        final JSONArray jsonCves = object.optJSONArray("cves");
        final List<String> stringCves = new ArrayList<>();
        if (jsonCves != null) {
            for (int j = 0; j < jsonCves.length(); j++) {
                stringCves.add(jsonCves.getString(j));
            }
            advisory.setCVEs(stringCves.toArray(new String[stringCves.size()]));
        }
        return advisory;
    }

}
