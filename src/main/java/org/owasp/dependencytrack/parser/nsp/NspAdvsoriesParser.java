/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
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
