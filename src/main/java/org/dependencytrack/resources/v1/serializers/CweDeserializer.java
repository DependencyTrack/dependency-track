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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1.serializers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.dependencytrack.model.Cwe;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Custom deserializer which takes in a Cwe object and returns a List of CWE IDs (Integer).
 * @since 4.5.0
 */
public class CweDeserializer extends JsonDeserializer<List<Integer>> {

    @Override
    public List<Integer> deserialize(JsonParser jsonParser, DeserializationContext ctx) throws IOException {
        if (jsonParser.getCurrentToken() == JsonToken.START_ARRAY) {
            final List<Integer> cweIds = new ArrayList<>();
            while(jsonParser.nextToken() != JsonToken.END_ARRAY) {
                if (jsonParser.getCurrentToken() == JsonToken.START_OBJECT) {
                    final Cwe cwe = jsonParser.readValueAs(Cwe.class);
                    if (cwe.getCweId() > 0) {
                        cweIds.add(cwe.getCweId());
                    }
                }
            }
            return cweIds;
        }
        return null;
    }
}
