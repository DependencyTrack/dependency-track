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
package org.dependencytrack.parser.vex;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Detects the {@link VexFormat} of a VEX document based on characteristics defined by the respective
 * specifications. Documents that cannot be attributed to any known format are rejected, rather than
 * being optimistically treated as CycloneDX.
 *
 * <ul>
 *     <li>CycloneDX documents are identified by their root element ({@code bom} in XML), respectively
 *     the mandatory {@code bomFormat} field in JSON.</li>
 *     <li>OpenVEX documents are identified by the mandatory JSON-LD {@code @context} field, which per
 *     specification points to the OpenVEX context definition at {@code https://openvex.dev/ns}.</li>
 * </ul>
 *
 * @since 5.7.0
 */
public final class VexFormatDetector {

    private static final Logger LOGGER = LoggerFactory.getLogger(VexFormatDetector.class);

    /**
     * URI of the JSON-LD context definition of OpenVEX documents.
     *
     * @see <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#document">OpenVEX Specification</a>
     */
    private static final String OPENVEX_CONTEXT_URI = "openvex.dev/ns";

    private static final String CYCLONEDX_BOM_FORMAT_FIELD = "bomFormat";
    private static final String CYCLONEDX_BOM_FORMAT_VALUE = "CycloneDX";

    private static final JsonMapper JSON_MAPPER = new JsonMapper();

    private VexFormatDetector() {
    }

    /**
     * @param vexBytes the raw VEX document
     * @return the detected format of the given document
     * @throws UnknownVexFormatException when the document is neither identifiable as CycloneDX nor as OpenVEX
     */
    public static VexFormat detect(final byte[] vexBytes) {
        if (looksLikeXml(vexBytes)) {
            // OpenVEX is JSON-only. Anything XML is routed through the CycloneDX tooling,
            // which reports precise errors when the document is not a valid CycloneDX BOM.
            return VexFormat.CYCLONEDX;
        }

        final JsonNode rootNode;
        try {
            rootNode = JSON_MAPPER.readTree(vexBytes);
        } catch (IOException e) {
            LOGGER.debug("Failed to parse VEX as JSON", e);
            throw new UnknownVexFormatException("""
                    Unable to identify the uploaded document as either CycloneDX or OpenVEX. \
                    The document is neither XML nor valid JSON\
                    """, e);
        }

        if (!rootNode.isObject()) {
            throw new UnknownVexFormatException("""
                    Unable to identify the uploaded document as either CycloneDX or OpenVEX. \
                    Expected the document to be a JSON object, but it is not\
                    """);
        }

        final JsonNode bomFormatNode = rootNode.get(CYCLONEDX_BOM_FORMAT_FIELD);
        if (bomFormatNode != null && bomFormatNode.isTextual()
                && CYCLONEDX_BOM_FORMAT_VALUE.equalsIgnoreCase(bomFormatNode.asText())) {
            return VexFormat.CYCLONEDX;
        }

        final JsonNode contextNode = rootNode.get("@context");
        if (contextNode != null && contextNode.isTextual()
                && contextNode.asText().contains(OPENVEX_CONTEXT_URI)) {
            return VexFormat.OPENVEX;
        }

        throw new UnknownVexFormatException("""
                Unable to identify the uploaded document as either CycloneDX or OpenVEX. \
                CycloneDX documents must declare "bomFormat": "CycloneDX", \
                and OpenVEX documents must declare an "@context" pointing to %s\
                """.formatted(OPENVEX_CONTEXT_URI));
    }

    private static boolean looksLikeXml(final byte[] vexBytes) {
        int offset = 0;
        if (vexBytes.length >= 3
                && vexBytes[0] == (byte) 0xEF
                && vexBytes[1] == (byte) 0xBB
                && vexBytes[2] == (byte) 0xBF) {
            offset = 3; // Skip the UTF-8 byte order mark, should there be any.
        }

        for (; offset < vexBytes.length; offset++) {
            final byte b = vexBytes[offset];
            if (b == ' ' || b == '\t' || b == '\r' || b == '\n') {
                continue; // Skip whitespace before the XML declaration or root element.
            }
            return b == '<';
        }

        return false;
    }

}
