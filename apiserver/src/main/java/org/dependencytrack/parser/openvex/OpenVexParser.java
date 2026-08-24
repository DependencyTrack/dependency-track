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
package org.dependencytrack.parser.openvex;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.dependencytrack.parser.openvex.OpenVexDocument.Component;
import org.dependencytrack.parser.openvex.OpenVexDocument.Identifiers;
import org.dependencytrack.parser.openvex.OpenVexDocument.Justification;
import org.dependencytrack.parser.openvex.OpenVexDocument.Product;
import org.dependencytrack.parser.openvex.OpenVexDocument.Statement;
import org.dependencytrack.parser.openvex.OpenVexDocument.Status;
import org.dependencytrack.parser.openvex.OpenVexDocument.Vulnerability;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Parses bytes into {@link OpenVexDocument}s, verifying conformance with version 0.2.0 of the
 * <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md">OpenVEX Specification</a>.
 *
 * <p>Validation follows the specification's requirements, aligned with those of the reference
 * implementation at <a href="https://github.com/openvex/go-vex">openvex/go-vex</a>. Unlike the
 * reference implementation, redundant fields (such as a justification on a {@code fixed} statement)
 * are tolerated rather than rejected, because they cannot lead to incorrect analyses being made.
 * All violations that ARE detected are collected before failing, so callers can report every
 * problem at once.
 *
 * <p>Fields unknown to the supported specification version are ignored, to remain forward-compatible.
 * Fields that carry no meaning for Dependency-Track (such as {@code hashes} or {@code subcomponents})
 * are parsed over, but not evaluated further.
 *
 * @since 5.7.0
 */
public final class OpenVexParser {

    /**
     * JSON-LD context of the only OpenVEX specification version supported by this parser.
     */
    static final String SUPPORTED_CONTEXT = "https://openvex.dev/ns/v0.2.0";

    private static final JsonMapper JSON_MAPPER = new JsonMapper();

    private OpenVexParser() {
    }

    /**
     * @param vexBytes the raw OpenVEX document
     * @return the parsed document
     * @throws OpenVexParseException when the document is not valid JSON, or violates the OpenVEX specification
     */
    public static OpenVexDocument parse(final byte[] vexBytes) throws OpenVexParseException {
        final JsonNode rootNode;
        try {
            rootNode = JSON_MAPPER.readTree(vexBytes);
        } catch (IOException e) {
            throw new OpenVexParseException("VEX is not valid JSON", e);
        }

        if (!rootNode.isObject()) {
            throw new OpenVexParseException("Expected the OpenVEX document to be a JSON object, but it is not");
        }

        final var validationErrors = new ArrayList<String>();

        // The JSON-LD context identifies both the format and the specification version,
        // and is thus required.
        final var context = requireString(rootNode, "@context", "/@context", validationErrors);
        if (!SUPPORTED_CONTEXT.equals(context)) {
            validationErrors.add("/@context: Unsupported OpenVEX specification version \"%s\"; Supported context is %s"
                    .formatted(context, SUPPORTED_CONTEXT));
        }

        final var id = requireString(rootNode, "@id", "/@id", validationErrors);
        final var author = requireString(rootNode, "author", "/author", validationErrors);
        final var role = optionalString(rootNode, "role", "/role", validationErrors);
        final var tooling = optionalString(rootNode, "tooling", "/tooling", validationErrors);
        final var timestamp = requireTimestamp(rootNode, "timestamp", "/timestamp", validationErrors);
        final int version = requireVersion(rootNode, "/version", validationErrors);

        final List<Statement> statements = parseStatements(rootNode.get("statements"), validationErrors);

        if (!validationErrors.isEmpty()) {
            throw new OpenVexParseException("The uploaded VEX is not a valid OpenVEX document", validationErrors);
        }

        return new OpenVexDocument(
                context,
                id,
                author,
                role,
                timestamp,
                version,
                tooling,
                statements);
    }

    private static List<Statement> parseStatements(final JsonNode statementsNode, final List<String> validationErrors) {
        if (statementsNode == null || statementsNode.isNull()) {
            validationErrors.add("/statements: Required field is missing");
            return List.of();
        }
        if (!statementsNode.isArray()) {
            validationErrors.add("/statements: Expected an array, but got %s".formatted(nodeType(statementsNode)));
            return List.of();
        }
        if (statementsNode.isEmpty()) {
            validationErrors.add("/statements: Must contain at least one statement");
            return List.of();
        }

        final var statements = new ArrayList<Statement>(statementsNode.size());
        for (int i = 0; i < statementsNode.size(); i++) {
            final String pathPrefix = "/statements/%d".formatted(i);
            final JsonNode statementNode = statementsNode.get(i);
            if (!statementNode.isObject()) {
                validationErrors.add("%s: Expected an object, but got %s".formatted(pathPrefix, nodeType(statementNode)));
                continue;
            }

            final var vulnerability = parseVulnerability(
                    statementNode.get("vulnerability"), pathPrefix, validationErrors);
            final var products = parseProducts(
                    statementNode.get("products"), pathPrefix, validationErrors);
            final var status = parseStatus(
                    statementNode.get("status"), pathPrefix, validationErrors);
            final var justification = parseJustification(
                    statementNode.get("justification"), pathPrefix, validationErrors);
            final var impactStatement = optionalString(
                    statementNode, "impact_statement", pathPrefix + "/impact_statement", validationErrors);
            final var actionStatement = optionalString(
                    statementNode, "action_statement", pathPrefix + "/action_statement", validationErrors);

            // Per specification and CISA minimum requirements for VEX, a "not_affected"
            // statement must inform WHY the product is not affected, and an "affected"
            // statement must describe the recommended action.
            if (status == Status.NOT_AFFECTED && justification == null && impactStatement == null) {
                validationErrors.add("""
                        %s: Either "justification" or "impact_statement" must be provided \
                        when using status "%s\"""".formatted(pathPrefix, Status.NOT_AFFECTED.getLabel()));
            } else if (status == Status.AFFECTED && actionStatement == null) {
                validationErrors.add("""
                        %s: "action_statement" must be provided when using status "%s\"""".formatted(pathPrefix, Status.AFFECTED.getLabel()));
            }

            statements.add(new Statement(vulnerability, products, status, justification, impactStatement, actionStatement));
        }

        return statements;
    }

    private static Vulnerability parseVulnerability(final JsonNode vulnNode, final String pathPrefix, final List<String> validationErrors) {
        if (vulnNode == null || vulnNode.isNull()) {
            validationErrors.add("%s/vulnerability: Required field is missing".formatted(pathPrefix));
            return new Vulnerability("", null, List.of());
        }
        if (!vulnNode.isObject()) {
            validationErrors.add("%s/vulnerability: Expected an object, but got %s".formatted(pathPrefix, nodeType(vulnNode)));
            return new Vulnerability("", null, List.of());
        }

        final var name = requireString(vulnNode, "name", pathPrefix + "/vulnerability/name", validationErrors);
        final var description = optionalString(vulnNode, "description", pathPrefix + "/vulnerability/description", validationErrors);

        final var aliases = new ArrayList<String>();
        final JsonNode aliasesNode = vulnNode.get("aliases");
        if (aliasesNode != null && !aliasesNode.isNull()) {
            if (aliasesNode.isArray()) {
                for (int i = 0; i < aliasesNode.size(); i++) {
                    final JsonNode aliasNode = aliasesNode.get(i);
                    if (aliasNode.isTextual() && !aliasNode.asText().isBlank()) {
                        aliases.add(aliasNode.asText());
                    } else {
                        validationErrors.add("%s/vulnerability/aliases/%d: Expected a non-blank string, but got %s"
                                .formatted(pathPrefix, i, nodeType(aliasNode)));
                    }
                }
            } else {
                validationErrors.add("%s/vulnerability/aliases: Expected an array, but got %s"
                        .formatted(pathPrefix, nodeType(aliasesNode)));
            }
        }

        return new Vulnerability(name, description, aliases);
    }

    private static List<Product> parseProducts(final JsonNode productsNode, final String pathPrefix, final List<String> validationErrors) {
        if (productsNode == null || productsNode.isNull()) {
            validationErrors.add("%s/products: Required field is missing".formatted(pathPrefix));
            return List.of();
        }
        if (!productsNode.isArray()) {
            validationErrors.add("%s/products: Expected an array, but got %s".formatted(pathPrefix, nodeType(productsNode)));
            return List.of();
        }
        if (productsNode.isEmpty()) {
            validationErrors.add("%s/products: Must contain at least one product".formatted(pathPrefix));
            return List.of();
        }

        final var products = new ArrayList<Product>(productsNode.size());
        for (int i = 0; i < productsNode.size(); i++) {
            final JsonNode productNode = productsNode.get(i);
            final String productPath = "%s/products/%d".formatted(pathPrefix, i);
            if (!productNode.isObject()) {
                validationErrors.add("%s: Expected an object, but got %s".formatted(productPath, nodeType(productNode)));
                continue;
            }

            products.add(new Product(
                    optionalString(productNode, "@id", productPath + "/@id", validationErrors),
                    parseIntoIdentifiers(productNode.get("identifiers"), productPath, validationErrors),
                    parseIntoSubcomponents(productNode.get("subcomponents"), productPath, validationErrors)));
        }

        return products;
    }

    private static @Nullable Identifiers parseIntoIdentifiers(final JsonNode identifiersNode, final String productPath, final List<String> validationErrors) {
        if (identifiersNode == null || identifiersNode.isNull()) {
            return null;
        }
        if (!identifiersNode.isObject()) {
            validationErrors.add("%s/identifiers: Expected an object, but got %s".formatted(productPath, nodeType(identifiersNode)));
            return null;
        }

        return new Identifiers(
                optionalString(identifiersNode, "purl", productPath + "/identifiers/purl", validationErrors),
                optionalString(identifiersNode, "cpe22", productPath + "/identifiers/cpe22", validationErrors),
                optionalString(identifiersNode, "cpe23", productPath + "/identifiers/cpe23", validationErrors));
    }

    private static List<Component> parseIntoSubcomponents(final JsonNode subcomponentsNode, final String productPath, final List<String> validationErrors) {
        if (subcomponentsNode == null || subcomponentsNode.isNull()) {
            return List.of();
        }
        if (!subcomponentsNode.isArray()) {
            validationErrors.add("%s/subcomponents: Expected an array, but got %s".formatted(productPath, nodeType(subcomponentsNode)));
            return List.of();
        }

        final var subcomponents = new ArrayList<Component>(subcomponentsNode.size());
        for (int i = 0; i < subcomponentsNode.size(); i++) {
            final JsonNode subcomponentNode = subcomponentsNode.get(i);
            final String subcomponentPath = "%s/subcomponents/%d".formatted(productPath, i);
            if (!subcomponentNode.isObject()) {
                validationErrors.add("%s: Expected an object, but got %s".formatted(subcomponentPath, nodeType(subcomponentNode)));
                continue;
            }

            subcomponents.add(new Component(
                    optionalString(subcomponentNode, "@id", subcomponentPath + "/@id", validationErrors),
                    parseIntoIdentifiers(subcomponentNode.get("identifiers"), subcomponentPath, validationErrors)));
        }

        return subcomponents;
    }

    private static Status parseStatus(final JsonNode statusNode, final String pathPrefix, final List<String> validationErrors) {
        if (statusNode == null || statusNode.isNull()) {
            validationErrors.add("%s/status: Required field is missing".formatted(pathPrefix));
            return Status.UNDER_INVESTIGATION;
        }
        if (!statusNode.isTextual()) {
            validationErrors.add("%s/status: Expected a string, but got %s".formatted(pathPrefix, nodeType(statusNode)));
            return Status.UNDER_INVESTIGATION;
        }

        final var label = statusNode.asText();
        return Status.fromLabel(label).orElseGet(() -> {
            validationErrors.add("%s/status: Unsupported status \"%s\"; Supported values are [%s]"
                    .formatted(pathPrefix, label, statusLabels()));
            return Status.UNDER_INVESTIGATION;
        });
    }

    private static @Nullable Justification parseJustification(final JsonNode justificationNode, final String pathPrefix, final List<String> validationErrors) {
        if (justificationNode == null || justificationNode.isNull()) {
            return null;
        }
        if (!justificationNode.isTextual()) {
            validationErrors.add("%s/justification: Expected a string, but got %s".formatted(pathPrefix, nodeType(justificationNode)));
            return null;
        }

        final var label = justificationNode.asText();
        return Justification.fromLabel(label).orElseGet(() -> {
            validationErrors.add("%s/justification: Unsupported justification \"%s\"; Supported values are [%s]"
                    .formatted(pathPrefix, label, justificationLabels()));
            return null;
        });
    }

    private static String requireTimestamp(final JsonNode parentNode, final String fieldName, final String fieldPath, final List<String> validationErrors) {
        final var value = requireString(parentNode, fieldName, fieldPath, validationErrors);
        if (value.isEmpty()) {
            return "";
        }

        try {
            OffsetDateTime.parse(value);
            return value;
        } catch (DateTimeParseException e) {
            validationErrors.add("%s: Not a valid ISO-8601 date-time: \"%s\"".formatted(fieldPath, value));
            return "";
        }
    }

    private static int requireVersion(final JsonNode parentNode, final String fieldPath, final List<String> validationErrors) {
        final JsonNode versionNode = parentNode.get("version");
        if (versionNode == null || versionNode.isNull()) {
            validationErrors.add("%s: Required field is missing".formatted(fieldPath));
            return -1;
        }
        if (!versionNode.isIntegralNumber() || !versionNode.canConvertToInt()) {
            validationErrors.add("%s: Expected an integer, but got %s".formatted(fieldPath, nodeType(versionNode)));
            return -1;
        }

        final int version = versionNode.intValue();
        if (version < 1) {
            validationErrors.add("%s: Version must be greater than zero, but was %d".formatted(fieldPath, version));
            return version;
        }

        return version;
    }

    private static String requireString(final JsonNode parentNode, final String fieldName, final String fieldPath, final List<String> validationErrors) {
        final JsonNode fieldNode = parentNode.get(fieldName);
        if (fieldNode == null || fieldNode.isNull()) {
            validationErrors.add("%s: Required field is missing".formatted(fieldPath));
            return "";
        }
        if (!fieldNode.isTextual() || fieldNode.asText().isBlank()) {
            validationErrors.add("%s: Expected a non-blank string, but got %s".formatted(fieldPath, nodeType(fieldNode)));
            return "";
        }

        return fieldNode.asText();
    }

    private static @Nullable String optionalString(final JsonNode parentNode, final String fieldName, final String fieldPath, final List<String> validationErrors) {
        final JsonNode fieldNode = parentNode.get(fieldName);
        if (fieldNode == null || fieldNode.isNull()) {
            return null;
        }
        if (!fieldNode.isTextual() || fieldNode.asText().isBlank()) {
            validationErrors.add("%s: Expected a non-blank string, but got %s".formatted(fieldPath, nodeType(fieldNode)));
            return null;
        }

        return fieldNode.asText();
    }

    private static String nodeType(final JsonNode node) {
        return switch (node.getNodeType()) {
            case ARRAY -> "an array";
            case BINARY -> "binary data";
            case BOOLEAN -> "a boolean";
            case MISSING -> "nothing";
            case NULL -> "null";
            case NUMBER -> "a number";
            case OBJECT -> "an object";
            case POJO -> "an object";
            case STRING -> "a string";
        };
    }

    private static String statusLabels() {
        return Arrays.stream(Status.values())
                .map(Status::getLabel)
                .collect(Collectors.joining(", "));
    }

    private static String justificationLabels() {
        return Arrays.stream(Justification.values())
                .map(Justification::getLabel)
                .collect(Collectors.joining(", "));
    }

}
