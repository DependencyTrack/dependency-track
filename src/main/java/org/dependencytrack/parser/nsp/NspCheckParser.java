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

import alpine.logging.Logger;
import io.github.openunirest.http.JsonNode;
import org.json.JSONArray;
import org.dependencytrack.parser.nsp.model.Advisory;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for Node Security Platform API response.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NspCheckParser extends BaseAdvisoryParser {

    private static final Logger LOGGER = Logger.getLogger(NspCheckParser.class);

    /**
     * Parses the JSON response from the NSP API.
     * @param jsonNode the JSON node to parse
     * @return an AdvisoryResults object
     */
    public List<Advisory> parse(JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");

        final List<Advisory> advisories = new ArrayList<>();
        final JSONArray root = jsonNode.getArray();
        for (int i = 0; i < root.length(); i++) {
            final Advisory advisory = super.parse(root.getJSONObject(i));
            advisories.add(advisory);
        }
        return advisories;
    }

}
