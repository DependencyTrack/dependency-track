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
package org.owasp.dependencytrack.parser.nsp;

import alpine.logging.Logger;
import com.mashape.unirest.http.JsonNode;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.dependencytrack.parser.nsp.model.AdvisoryResults;
import org.owasp.dependencytrack.parser.nsp.model.Advisory;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for Node Security Platform API response.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NspAdvsoriesParser {

    private static final Logger LOGGER = Logger.getLogger(NspAdvsoriesParser.class);

    /**
     * Parses the JSON response from the NSP API.
     * @param jsonNode the JSON node to parse
     * @return an AdvisoryResults object
     */
    public AdvisoryResults parse(JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");

        final AdvisoryResults advisories = new AdvisoryResults();
        final JSONObject root = jsonNode.getObject();
        advisories.setOffset(root.getInt("offset"));
        advisories.setTotal(root.getInt("total"));
        advisories.setCount(root.getInt("count"));
        final JSONArray results = root.getJSONArray("results");

        if (results != null) {
            for (int i = 0; i < results.length(); i++) {
                final JSONObject object = results.getJSONObject(i);
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
                //todo: allowed_scopes ??? what is this ???
                advisory.setModuleName(object.optString("module_name", null));
                advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
                advisory.setPatchedVersions(object.optString("patched_versions", null));
                advisory.setPublishDate(object.optString("publish_date", null));
                advisory.setSlug(object.optString("slug", null));
                advisory.setLegacySlug(object.optString("legacy_slug", null));


                final JSONArray jsonCves = object.optJSONArray("cves");
                final List<String> stringCves = new ArrayList<>();
                if (jsonCves != null) {
                    for (int j = 0; j < jsonCves.length(); j++) {
                        stringCves.add(jsonCves.getString(j));
                    }
                    advisory.setCVEs(stringCves.toArray(new String[stringCves.size()]));
                }

                advisories.add(advisory);
            }
        }
        return advisories;
    }
}
