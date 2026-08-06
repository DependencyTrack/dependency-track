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
package org.dependencytrack.parser.cyclonedx;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test-only assertions that enforce CycloneDX specification rules JSON Schema cannot express.
 *
 * <p>The CycloneDX 1.5+ schema description on every {@code bom-ref}-bearing object states that
 * "Every bom-ref MUST be unique within the BOM" — across {@code metadata.component},
 * {@code components[]}, {@code services[]}, and {@code vulnerabilities[]}. JSON Schema draft-07
 * cannot express cross-property uniqueness, so producers must be guarded by separate test-side
 * assertions like the one below.
 */
public final class CycloneDxBomAssertions {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CycloneDxBomAssertions() {
    }

    /**
     * Assert that every {@code bom-ref} value appearing anywhere in the BOM is unique across the
     * whole document.
     *
     * @param json the serialised CycloneDX BOM
     * @throws AssertionError if any {@code bom-ref} value occurs more than once, or the BOM cannot
     *                        be parsed
     */
    public static void assertBomRefsUnique(final String json) {
        final JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (Exception e) {
            throw new AssertionError("Failed to parse BOM JSON for bom-ref uniqueness check", e);
        }
        final Map<String, List<String>> refToPaths = new LinkedHashMap<>();
        collectBomRefs(root, "$", refToPaths);

        final Map<String, List<String>> duplicates = new LinkedHashMap<>();
        refToPaths.forEach((ref, paths) -> {
            if (paths.size() > 1) {
                duplicates.put(ref, paths);
            }
        });
        Assertions.assertThat(duplicates)
                .as("CycloneDX bom-refs that appear more than once across the document; "
                        + "value -> JSON paths where the duplicate occurred")
                .isEmpty();
    }

    private static void collectBomRefs(final JsonNode node, final String path,
                                       final Map<String, List<String>> sink) {
        if (node == null) {
            return;
        }
        if (node.isObject()) {
            final JsonNode ref = node.get("bom-ref");
            if (ref != null && ref.isTextual()) {
                sink.computeIfAbsent(ref.asText(), k -> new ArrayList<>()).add(path);
            }
            node.fields().forEachRemaining(entry ->
                    collectBomRefs(entry.getValue(), path + appendKey(entry.getKey()), sink));
        } else if (node.isArray()) {
            int i = 0;
            for (final JsonNode child : node) {
                collectBomRefs(child, path + "[" + i + "]", sink);
                i++;
            }
        }
    }

    /**
     * Render a JSON object key as a path segment. Plain identifiers use dot-notation
     * ({@code .foo}); keys with characters that would make the dot form ambiguous —
     * {@code .}, {@code [}, {@code ]}, {@code "}, or whitespace — fall back to bracket
     * notation with the key escaped ({@code ["foo.bar"]}).
     */
    private static String appendKey(final String key) {
        for (int i = 0; i < key.length(); i++) {
            final char c = key.charAt(i);
            if (c == '.' || c == '[' || c == ']' || c == '"' || Character.isWhitespace(c)) {
                return "[\"" + key.replace("\\", "\\\\").replace("\"", "\\\"") + "\"]";
            }
        }
        return "." + key;
    }
}
