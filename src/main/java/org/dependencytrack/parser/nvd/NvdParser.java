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
package org.dependencytrack.parser.nvd;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.function.BiConsumer;

import static org.dependencytrack.parser.nvd.api20.ModelConverter.convert;
import static org.dependencytrack.parser.nvd.api20.ModelConverter.convertConfigurations;

/**
 * Parser and processor of NVD data feeds.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class NvdParser {

    private static final Logger LOGGER = Logger.getLogger(NvdParser.class);

    // TODO: Use global ObjectMapper instance once
    // https://github.com/DependencyTrack/dependency-track/pull/2520
    // is merged.
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature(), true)
            .registerModule(new JavaTimeModule());
    private final BiConsumer<Vulnerability, List<VulnerableSoftware>> vulnerabilityConsumer;

    public NvdParser(final BiConsumer<Vulnerability, List<VulnerableSoftware>> vulnerabilityConsumer) {
        this.vulnerabilityConsumer = vulnerabilityConsumer;
    }

    public void parse(final File file) {
        if (!file.getName().endsWith(".json")) {
            return;
        }

        LOGGER.info("Parsing " + file.getName());

        try (final InputStream in = Files.newInputStream(file.toPath());
             final JsonParser jsonParser = objectMapper.createParser(in)) {
            jsonParser.nextToken(); // Position cursor at first token

            // Due to JSON feeds being rather large, do not parse them completely,
            // but "stream" through them. Parsing individual CVE items
            // one-by-one allows for garbage collection to kick in sooner,
            // keeping the overall memory footprint low.
            JsonToken currentToken;
            while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
                final String fieldName = jsonParser.currentName();
                currentToken = jsonParser.nextToken();
                if ("vulnerabilities".equals(fieldName)) {
                    if (currentToken == JsonToken.START_ARRAY) {
                        while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                            final var defCveItem = objectMapper.readValue(jsonParser, DefCveItem.class);
                            parseCveItem(defCveItem.getCve());
                        }
                    } else {
                        jsonParser.skipChildren();
                    }
                } else {
                    jsonParser.skipChildren();
                }
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred while parsing NVD JSON data", e);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private void parseCveItem(final CveItem cveItem) {
        final Vulnerability vulnerability = convert(cveItem);
        final List<VulnerableSoftware> vsList = convertConfigurations(
                cveItem.getId(), cveItem.getConfigurations());
        vulnerabilityConsumer.accept(vulnerability, vsList);
    }

}
