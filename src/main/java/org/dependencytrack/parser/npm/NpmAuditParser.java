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

import alpine.logging.Logger;
import io.github.openunirest.http.JsonNode;
import org.dependencytrack.parser.npm.model.Advisory;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for NPM Advisory objects returned from the NPM Audit API.
 *
 * @author Steve Springett
 * @since 3.2.1
 */
public class NpmAuditParser extends BaseAdvisoryParser {

    private static final Logger LOGGER = Logger.getLogger(NpmAuditParser.class);

    /**
     * Parses the JSON response from the NPM Audit API.
     *
     * @param jsonNode the JSON node to parse
     * @return an AdvisoryResults object
     * @
     */
    public List<Advisory> parse(JsonNode jsonNode) {
        LOGGER.debug("Parsing JSON node");
        List<Advisory> advisories = new ArrayList<>();
        JSONObject jsonAdvisories = jsonNode.getObject().getJSONObject("advisories");
        for (String key : jsonAdvisories.keySet()) {
            Advisory advisory = super.parse(jsonAdvisories.getJSONObject(key));
            advisories.add(advisory);
        }
        return advisories;
    }
}
