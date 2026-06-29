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
package org.dependencytrack.kevdatasource.cisa;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.jsonfeed.AbstractJsonFeedKevDataSource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/// Consumes the CISA Known Exploited Vulnerabilities JSON catalog.
///
/// @see [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
/// @since 5.1.0
final class CisaKevDataSource extends AbstractJsonFeedKevDataSource {

    CisaKevDataSource(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI feedUrl) {
        super(httpClient, objectMapper, feedUrl);
    }

    @Override
    protected List<KevAssertion> parseEntries(JsonParser jsonParser) throws IOException {
        jsonParser.nextToken(); // Position cursor at first token.
        final var assertions = new ArrayList<KevAssertion>();

        while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
            final String fieldName = jsonParser.currentName();
            final JsonToken valueToken = jsonParser.nextToken();
            if (!"vulnerabilities".equals(fieldName) || valueToken != JsonToken.START_ARRAY) {
                jsonParser.skipChildren();
                continue;
            }

            while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                final JsonNode entryNode = jsonParser.readValueAsTree();
                assertions.add(toKevAssertion(entryNode));
            }
        }

        return assertions;
    }

    private KevAssertion toKevAssertion(JsonNode entryNode) throws IOException {
        final var entry = objectMapper.treeToValue(entryNode, CisaKevEntry.class);

        return new KevAssertion(
                "NVD",
                entry.cveId(),
                // NB: CISA doesn't specify the timezone of `dateAdded`. UTC is an educated guess.
                entry.dateAdded().atStartOfDay(ZoneOffset.UTC).toInstant(),
                entry.requiredAction(),
                "known".equalsIgnoreCase(entry.knownRansomwareCampaignUse()) ? true : null,
                entry.shortDescription(),
                entryNode);
    }

}
