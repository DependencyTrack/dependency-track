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

import alpine.common.logging.Logger;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.codehaus.stax2.XMLInputFactory2;
import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.Parser;
import org.cyclonedx.parsers.XmlParser;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.cyclonedx.CycloneDxSchema.NS_BOM_10;
import static org.cyclonedx.CycloneDxSchema.NS_BOM_11;
import static org.cyclonedx.CycloneDxSchema.NS_BOM_12;
import static org.cyclonedx.CycloneDxSchema.NS_BOM_13;
import static org.cyclonedx.CycloneDxSchema.NS_BOM_14;
import static org.cyclonedx.CycloneDxSchema.NS_BOM_15;
import static org.cyclonedx.CycloneDxSchema.NS_BOM_16;
import static org.cyclonedx.Version.VERSION_10;
import static org.cyclonedx.Version.VERSION_11;
import static org.cyclonedx.Version.VERSION_12;
import static org.cyclonedx.Version.VERSION_13;
import static org.cyclonedx.Version.VERSION_14;
import static org.cyclonedx.Version.VERSION_15;
import static org.cyclonedx.Version.VERSION_16;

/**
 * @since 4.11.0
 */
public class CycloneDxValidator {

    private static final Logger LOGGER = Logger.getLogger(CycloneDxValidator.class);
    private static final CycloneDxValidator INSTANCE = new CycloneDxValidator();

    private final JsonMapper jsonMapper = new JsonMapper();

    CycloneDxValidator() {
    }

    public static CycloneDxValidator getInstance() {
        return INSTANCE;
    }

    public void validate(final byte[] bomBytes) {
        final FormatAndVersion formatAndVersion = detectFormatAndSchemaVersion(bomBytes);

        final Parser bomParser = switch (formatAndVersion.format()) {
            case JSON -> new JsonParser();
            case XML -> new XmlParser();
        };

        final List<ParseException> validationErrors;
        try {
            validationErrors = bomParser.validate(bomBytes, formatAndVersion.version());
        } catch (IOException e) {
            throw new RuntimeException("Failed to validate BOM", e);
        }

        if (!validationErrors.isEmpty()) {
            throw new InvalidBomException("Schema validation failed", validationErrors.stream()
                    .map(ParseException::getMessage)
                    .toList());
        }
    }

    private FormatAndVersion detectFormatAndSchemaVersion(final byte[] bomBytes) {
        try {
            final Version version = detectSchemaVersionFromJson(bomBytes);
            return new FormatAndVersion(Format.JSON, version);
        } catch (JsonParseException e) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Failed to parse BOM as JSON", e);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            final Version version = detectSchemaVersionFromXml(bomBytes);
            return new FormatAndVersion(Format.XML, version);
        } catch (XMLStreamException e) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Failed to parse BOM as XML", e);
            }
        }

        throw new InvalidBomException("BOM is neither valid JSON nor XML");
    }

    private Version detectSchemaVersionFromJson(final byte[] bomBytes) throws IOException {
        try (final com.fasterxml.jackson.core.JsonParser jsonParser = jsonMapper.createParser(bomBytes)) {
            JsonToken currentToken = jsonParser.nextToken();
            if (currentToken != JsonToken.START_OBJECT) {
                final String currentTokenAsString = Optional.ofNullable(currentToken)
                        .map(JsonToken::asString).orElse(null);
                throw new JsonParseException(jsonParser, "Expected token %s, but got %s"
                        .formatted(JsonToken.START_OBJECT.asString(), currentTokenAsString));
            }

            Version schemaVersion = null;
            while (jsonParser.nextToken() != null) {
                final String fieldName = jsonParser.currentName();
                if ("specVersion".equals(fieldName)) {
                    if (jsonParser.nextToken() == JsonToken.VALUE_STRING) {
                        final String specVersion = jsonParser.getValueAsString();
                        schemaVersion = switch (jsonParser.getValueAsString()) {
                            case "1.0", "1.1" ->
                                    throw new InvalidBomException("JSON is not supported for specVersion %s".formatted(specVersion));
                            case "1.2" -> VERSION_12;
                            case "1.3" -> VERSION_13;
                            case "1.4" -> VERSION_14;
                            case "1.5" -> VERSION_15;
                            case "1.6" -> VERSION_16;
                            default ->
                                    throw new InvalidBomException("Unrecognized specVersion %s".formatted(specVersion));
                        };
                    }
                }

                if (schemaVersion != null) {
                    return schemaVersion;
                }
            }

            throw new InvalidBomException("Unable to determine schema version from JSON");
        }
    }

    private Version detectSchemaVersionFromXml(final byte[] bomBytes) throws XMLStreamException {
        final XMLInputFactory xmlInputFactory = XMLInputFactory2.newFactory();
        final var bomBytesStream = new ByteArrayInputStream(bomBytes);
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(bomBytesStream);

        Version schemaVersion = null;
        while (xmlStreamReader.hasNext()) {
            if (xmlStreamReader.next() == XMLEvent.START_ELEMENT) {
                if (!"bom".equalsIgnoreCase(xmlStreamReader.getLocalName())) {
                    continue;
                }

                final var namespaceUrisSeen = new ArrayList<String>();
                for (int i = 0; i < xmlStreamReader.getNamespaceCount(); i++) {
                    final String namespaceUri = xmlStreamReader.getNamespaceURI(i);
                    namespaceUrisSeen.add(namespaceUri);

                    schemaVersion = switch (namespaceUri) {
                        case NS_BOM_10 -> VERSION_10;
                        case NS_BOM_11 -> VERSION_11;
                        case NS_BOM_12 -> VERSION_12;
                        case NS_BOM_13 -> VERSION_13;
                        case NS_BOM_14 -> VERSION_14;
                        case NS_BOM_15 -> VERSION_15;
                        case NS_BOM_16 -> VERSION_16;
                        default -> null;
                    };
                }

                if (schemaVersion == null) {
                    throw new InvalidBomException("Unable to determine schema version from XML namespaces %s"
                            .formatted(namespaceUrisSeen));
                }

                break;
            }
        }

        if (schemaVersion == null) {
            throw new InvalidBomException("Unable to determine schema version from XML");
        }

        return schemaVersion;
    }

    private enum Format {
        JSON,
        XML
    }

    private record FormatAndVersion(Format format, Version version) {
    }

}
