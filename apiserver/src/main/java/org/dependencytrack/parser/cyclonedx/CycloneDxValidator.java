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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import javax.xml.transform.stax.StAXSource;
import javax.xml.validation.Validator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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

    private static final Logger LOGGER = LoggerFactory.getLogger(CycloneDxValidator.class);
    private static final CycloneDxValidator INSTANCE = new CycloneDxValidator();

    private final JsonMapper jsonMapper = new JsonMapper();
    private final XMLInputFactory xmlInputFactory = createXmlInputFactory();
    private final CycloneDxSchema schemaSource = new JsonParser();
    private final Map<Version, com.networknt.schema.Schema> jsonSchemaCache = new ConcurrentHashMap<>();
    private final Map<Version, javax.xml.validation.Schema> xmlSchemaCache = new ConcurrentHashMap<>();

    CycloneDxValidator() {
    }

    public static CycloneDxValidator getInstance() {
        return INSTANCE;
    }

    public void validate(byte[] bomBytes) {
        final FormatAndVersion formatAndVersion = detectFormatAndSchemaVersion(bomBytes);
        final List<String> validationErrors = switch (formatAndVersion.format()) {
            case JSON -> validateJson(bomBytes, formatAndVersion.version());
            case XML -> validateXml(bomBytes, formatAndVersion.version());
        };
        if (!validationErrors.isEmpty()) {
            throw new InvalidBomException("Schema validation failed", validationErrors);
        }
    }

    private List<String> validateJson(byte[] bomBytes, Version version) {
        final com.networknt.schema.Schema schema =
                jsonSchemaCache.computeIfAbsent(version, this::loadJsonSchema);

        final JsonNode bomNode;
        try {
            bomNode = jsonMapper.readTree(bomBytes);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse BOM", e);
        }

        return schema.validate(bomNode).stream()
                .map(error -> error.getInstanceLocation() != null && error.getInstanceLocation().getNameCount() > 0
                        ? "%s: %s".formatted(error.getInstanceLocation(), error.getMessage())
                        : error.getMessage())
                .toList();
    }

    private List<String> validateXml(byte[] bomBytes, Version version) {
        final javax.xml.validation.Schema schema =
                xmlSchemaCache.computeIfAbsent(version, this::loadXmlSchema);

        // NB: Validator is not thread-safe.
        final Validator validator = schema.newValidator();
        try {
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException e) {
            throw new IllegalStateException("Failed to harden XML validator", e);
        }

        final var validationErrors = new ArrayList<String>();
        validator.setErrorHandler(new ErrorHandler() {
            @Override
            public void warning(final SAXParseException e) {
                validationErrors.add(e.getMessage());
            }

            @Override
            public void error(final SAXParseException e) {
                validationErrors.add(e.getMessage());
            }

            @Override
            public void fatalError(final SAXParseException e) {
                validationErrors.add(e.getMessage());
            }
        });

        try {
            final XMLStreamReader streamReader =
                    xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(bomBytes));
            validator.validate(new StAXSource(streamReader));
        } catch (SAXException | XMLStreamException | IOException e) {
            throw new IllegalStateException("Failed to validate BOM", e);
        }

        return validationErrors;
    }

    private com.networknt.schema.Schema loadJsonSchema(Version version) {
        try {
            return schemaSource.getJsonSchema(version, jsonMapper);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load CycloneDX JSON schema for " + version, e);
        }
    }

    private javax.xml.validation.Schema loadXmlSchema(Version version) {
        try {
            return schemaSource.getXmlSchema(version);
        } catch (SAXException e) {
            throw new IllegalStateException("Failed to load CycloneDX XML schema for " + version, e);
        }
    }

    private FormatAndVersion detectFormatAndSchemaVersion(byte[] bomBytes) {
        final var suppressedExceptions = new ArrayList<Exception>(2);

        try {
            final Version version = detectSchemaVersionFromJson(bomBytes);
            return new FormatAndVersion(Format.JSON, version);
        } catch (JsonParseException e) {
            suppressedExceptions.add(e);
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
            suppressedExceptions.add(e);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Failed to parse BOM as XML", e);
            }
        }

        final var exception = new InvalidBomException("BOM is neither valid JSON nor XML");
        suppressedExceptions.forEach(exception::addSuppressed);
        throw exception;
    }

    private Version detectSchemaVersionFromJson(byte[] bomBytes) throws IOException {
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

    private Version detectSchemaVersionFromXml(byte[] bomBytes) throws XMLStreamException {
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

                    if (schemaVersion != null) {
                        break;
                    }
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

    private static XMLInputFactory createXmlInputFactory() {
        final var factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return factory;
    }

}