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
package org.dependencytrack.kevdatasource.enisa;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.jsonfeed.AbstractJsonFeedKevDataSource;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/// Consumes ENISA's EU KEV catalog.
///
/// @see [ENISA EU KEV](https://github.com/enisaeu/CNW/tree/main/advisories/eukev)
/// @since 5.1.0
final class EnisaKevDataSource extends AbstractJsonFeedKevDataSource {

    EnisaKevDataSource(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI feedUrl) {
        super(httpClient, objectMapper, feedUrl);
    }

    @Override
    protected List<KevAssertion> parseEntries(JsonParser jsonParser) throws IOException {
        if (jsonParser.nextToken() != JsonToken.START_ARRAY) {
            return List.of();
        }

        final var assertions = new ArrayList<KevAssertion>();
        while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
            final JsonNode entryNode = jsonParser.readValueAsTree();

            final KevAssertion assertion = toKevAssertion(entryNode);
            if (assertion != null) {
                assertions.add(assertion);
            }
        }

        return assertions;
    }

    private @Nullable KevAssertion toKevAssertion(JsonNode entryNode) throws IOException {
        final var entry = objectMapper.treeToValue(entryNode, EnisaKevEntry.class);
        if (entry.cveId() == null) {
            // TODO: cveId is nullable per schema, but euvdId is not.
            //  We don't currently support EUVD identifiers so entries
            //  without CVE are skipped for now.
            return null;
        }

        return new KevAssertion(
                "NVD",
                entry.cveId(),
                // NB: ENISA doesn't specify the timezone of `dateReported`. UTC is an educated guess.
                // Requested clarification at https://github.com/enisaeu/CNW/issues/57
                entry.dateReported().atStartOfDay(ZoneOffset.UTC).toInstant(),
                /* requiredAction */ null,
                "ransomware".equalsIgnoreCase(entry.exploitationType()) ? true : null,
                entry.shortDescription(),
                entryNode);
    }

}
