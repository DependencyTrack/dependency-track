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

import org.dependencytrack.parser.openvex.model.Openvex;
import org.dependencytrack.parser.openvex.model.Statement;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OpenVexParserTest {

    @Test
    void shouldParseMinimalValidDocument() {
        final Openvex document = parse(/* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "role": "Document Creator",
                  "timestamp": "2023-01-08T18:02:03.647787998-06:00",
                  "version": 1,
                  "statements": [
                    {
                      "vulnerability": {
                        "name": "CVE-2023-12345"
                      },
                      "products": [
                        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"}
                      ],
                      "status": "fixed"
                    }
                  ]
                }
                """);

        assertThat(document.getContext()).isEqualTo("https://openvex.dev/ns/v0.2.0");
        assertThat(OpenVexParser.specVersion(document)).isEqualTo("0.2.0");
        assertThat(document.getId()).isEqualTo("https://openvex.dev/docs/example/vex-9fb3463de1b57");
        assertThat(document.getAuthor()).isEqualTo("Wolfi J Inkinson");
        assertThat(document.getRole()).isEqualTo("Document Creator");
        assertThat(document.getTimestamp()).isEqualTo("2023-01-08T18:02:03.647787998-06:00");
        assertThat(document.getVersion()).isEqualTo(1);
        assertThat(document.getTooling()).isNull();
        assertThat(document.getStatements()).hasSize(1);

        final var statement = document.getStatements().getFirst();
        assertThat(statement.getVulnerability().getName()).isEqualTo("CVE-2023-12345");
        assertThat(statement.getStatus()).isEqualTo(Statement.Status.FIXED);
        assertThat(statement.getProducts()).hasSize(1);
        assertThat(statement.getProducts().getFirst().getId())
                .isEqualTo("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7");
    }

    @Test
    void shouldParseDocumentWithMultipleStatements() {
        final Openvex document = parse(/* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-08T18:02:03-06:00",
                  "version": 2,
                  "tooling": "vexctl",
                  "statements": [
                    {
                      "timestamp": "2023-01-08T18:02:03-06:00",
                      "vulnerability": { "name": "CVE-2023-12345" },
                      "products": [{"@id": "pkg:apk/wolfi/git@2.39.0-r1"}],
                      "status": "under_investigation"
                    },
                    {
                      "vulnerability": { "name": "CVE-2023-12345" },
                      "products": [
                        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"},
                        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"}
                      ],
                      "status": "fixed"
                    }
                  ]
                }
                """);

        assertThat(document.getStatements()).hasSize(2);
        assertThat(document.getStatements().get(0).getTimestamp()).isEqualTo("2023-01-08T18:02:03-06:00");
        assertThat(document.getStatements().get(0).getStatus())
                .isEqualTo(Statement.Status.UNDER_INVESTIGATION);
        assertThat(document.getStatements().get(1).getProducts()).hasSize(2);
    }

    @Test
    void shouldParseVulnerabilityWithAliasesAndDescription() {
        final Openvex document = parse(minimalDoc("""
                "vulnerability": {
                   "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                   "name": "CVE-2021-44228",
                   "description": "Remote code injection in Log4j",
                   "aliases": ["GHSA-jfh8-c2jp-5v3q", "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314721"]
                 },
                 "products": [{"@id": "pkg:apk/wolfi/git@2.39.0-r1"}],
                 "status": "fixed" """));

        final var vulnerability = document.getStatements().getFirst().getVulnerability();
        assertThat(vulnerability.getName()).isEqualTo("CVE-2021-44228");
        assertThat(vulnerability.getDescription()).isEqualTo("Remote code injection in Log4j");
        assertThat(vulnerability.getAliases()).containsExactly(
                "GHSA-jfh8-c2jp-5v3q", "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314721");
    }

    @Test
    void shouldParseProductWithIdentifiers() {
        final Openvex document = parse(minimalDoc("""
                "vulnerability": {"name": "CVE-2023-12345"},
                 "products": [
                   {
                     "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.4",
                     "identifiers": {
                       "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.4",
                       "cpe22": "cpe:/a:apache:log4j:2.4:-",
                       "cpe23": "cpe:2.3:a:apache:log4j:2.4:-:*:*:*:*:*:*"
                     }
                   }
                 ],
                 "status": "fixed" """));

        final var identifiers = document.getStatements().getFirst().getProducts().getFirst().getIdentifiers();
        assertThat(identifiers.getPurl()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.4");
        assertThat(identifiers.getCpe22()).isEqualTo("cpe:/a:apache:log4j:2.4:-");
        assertThat(identifiers.getCpe23()).isEqualTo("cpe:2.3:a:apache:log4j:2.4:-:*:*:*:*:*:*");
    }

    @Test
    void shouldTolerateUnknownFields() {
        final Openvex document = parse(/* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-08T18:02:03-06:00",
                  "version": 1,
                  "last_updated": "2023-01-09T09:08:42-06:00",
                  "supplier": "Some Supplier",
                  "statements": [
                    {
                      "@id": "https://openvex.dev/docs/example/statements/s1",
                      "version": 3,
                      "supplier": "Some Other Supplier",
                      "status_notes": "Determined by scanning",
                      "last_updated": "2023-01-09T09:08:42-06:00",
                      "action_statement_timestamp": "2023-01-09T09:08:42-06:00",
                      "vulnerability": { "name": "CVE-2023-12345" },
                      "products": [
                        {
                          "@id": "pkg:apk/wolfi/git@2.39.0-r1",
                          "hashes": {
                            "sha-256": "402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856"
                          }
                        }
                      ],
                      "status": "affected",
                      "action_statement": "Upgrade to version 2.40.0"
                    }
                  ]
                }
                """);

        assertThat(document.getStatements()).hasSize(1);
        assertThat(document.getStatements().getFirst().getStatusNotes()).isEqualTo("Determined by scanning");
        assertThat(document.getStatements().getFirst().getActionStatement()).isEqualTo("Upgrade to version 2.40.0");
    }

    @Test
    void shouldFailForInvalidJson() {
        assertThatThrownBy(() -> OpenVexParser.parse("{invalid".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .hasMessageContaining("not valid JSON")
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors()).isEmpty());
    }

    @Test
    void shouldFailWhenRootIsNotAnObject() {
        assertThatThrownBy(() -> OpenVexParser.parse("[1, 2, 3]".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .hasMessageContaining("Expected the OpenVEX document to be a JSON object");
    }

    @Test
    void shouldCollectMissingRequiredFields() {
        assertThatThrownBy(() -> OpenVexParser.parse("{}".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .hasMessageContaining("not a valid OpenVEX document")
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors()).contains(
                        "required property '@context' not found",
                        "required property '@id' not found",
                        "required property 'author' not found",
                        "required property 'timestamp' not found",
                        "required property 'version' not found",
                        "required property 'statements' not found"));
    }

    @Test
    void shouldFailForUnsupportedSpecVersion() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"fixed\""
        ).replace("https://openvex.dev/ns/v0.2.0", "https://openvex.dev/ns/v0.3.0")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .contains("'https://openvex.dev/ns/v0.2.0'")));
    }

    @Test
    void shouldFailForEmptyStatements() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDocWithoutStatements()
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .contains("/statements")
                                .contains("at least 1")));
    }

    @Test
    void shouldFailForInvalidTimestamp() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"fixed\"")
                .replace("\"timestamp\": \"2023-01-08T18:02:03-06:00\"", "\"timestamp\": \"not-a-date\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("/timestamp: Not a valid ISO-8601 date-time: \"not-a-date\""));
    }

    @Test
    void shouldFailForNonPositiveVersion() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDocWithoutStatements()
                .replace("\"version\": 1", "\"version\": 0")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .contains("/version")
                                .contains("minimum value of 1")));
    }

    @Test
    void shouldFailForMissingStatus() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}]")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .startsWith("/statements/0")
                                .contains("required property 'status' not found")));
    }

    @Test
    void shouldFailForUnsupportedStatus() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                """
                        "vulnerability": {"name": "CVE-2023-12345"}, \
                        "products": [{"@id": "pkg:x/y@1"}], \
                        "status": "resolved\"""")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .startsWith("/statements/0/status")
                                .contains("does not have a value in the enumeration",
                                        "\"not_affected\"", "\"affected\"", "\"fixed\"", "\"under_investigation\"")));
    }

    @Test
    void shouldFailForUnsupportedJustification() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                """
                        "vulnerability": {"name": "CVE-2023-12345"}, \
                        "products": [{"@id": "pkg:x/y@1"}], \
                        "status": "fixed", \
                        "justification": "code_not_present\"""")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .startsWith("/statements/0/justification")
                                .contains("code_not_present")
                                .contains("component_not_present")));
    }

    @Test
    void shouldFailForNotAffectedWithoutJustificationOrImpactStatement() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"not_affected\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error).startsWith("/statements/0")));
    }

    @Test
    void shouldAcceptNotAffectedWithImpactStatementOnly() {
        final Openvex document = parse(minimalDoc(
                """
                        "vulnerability": {"name": "CVE-2023-12345"}, \
                        "products": [{"@id": "pkg:x/y@1"}], \
                        "status": "not_affected", \
                        "impact_statement": "Not exploitable as shipped\""""));

        assertThat(document.getStatements().getFirst().getStatus())
                .isEqualTo(Statement.Status.NOT_AFFECTED);
        assertThat(document.getStatements().getFirst().getJustification()).isNull();
        assertThat(document.getStatements().getFirst().getImpactStatement()).isEqualTo("Not exploitable as shipped");
    }

    @Test
    void shouldFailForAffectedWithoutActionStatement() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"affected\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .startsWith("/statements/0")
                                .contains("required property 'action_statement' not found")));
    }

    @Test
    void shouldParseStatementWithoutProducts() {
        final Openvex document = parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"status\": \"fixed\""));

        assertThat(document.getStatements()).hasSize(1);
        assertThat(document.getStatements().getFirst().getStatus())
                .isEqualTo(Statement.Status.FIXED);
        assertThat(document.getStatements().getFirst().getProducts()).isEmpty();
    }

    @Test
    void shouldFailWhenProductsAreMissingOrEmpty() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [], \"status\": \"fixed\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .startsWith("/statements/0/products")
                                .contains("at least 1")));
    }

    @Test
    void shouldFailForMissingVulnerabilityName() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"fixed\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .anySatisfy(error -> assertThat(error)
                                .startsWith("/statements/0/vulnerability")
                                .contains("required property 'name' not found")));
    }

    private static Openvex parse(final String json) {
        return OpenVexParser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Wraps the given statement fields (as raw JSON) into a minimal, otherwise valid OpenVEX document.
     */
    private static String minimalDoc(final String statementFields) {
        return /* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-08T18:02:03-06:00",
                  "version": 1,
                  "statements": [
                    {
                      %s
                    }
                  ]
                }
                """.formatted(statementFields);
    }

    private static String minimalDocWithoutStatements() {
        return /* language=JSON */ """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                  "author": "Wolfi J Inkinson",
                  "timestamp": "2023-01-08T18:02:03-06:00",
                  "version": 1,
                  "statements": []
                }
                """;
    }

}
