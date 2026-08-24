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

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OpenVexParserTest {

    @Test
    void shouldParseMinimalValidDocument() {
        final OpenVexDocument document = parse(/* language=JSON */ """
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

        assertThat(document.context()).isEqualTo("https://openvex.dev/ns/v0.2.0");
        assertThat(document.specVersion()).isEqualTo("0.2.0");
        assertThat(document.id()).isEqualTo("https://openvex.dev/docs/example/vex-9fb3463de1b57");
        assertThat(document.author()).isEqualTo("Wolfi J Inkinson");
        assertThat(document.role()).isEqualTo("Document Creator");
        assertThat(document.timestamp()).isEqualTo("2023-01-08T18:02:03.647787998-06:00");
        assertThat(document.version()).isEqualTo(1);
        assertThat(document.tooling()).isNull();
        assertThat(document.statements()).hasSize(1);

        final var statement = document.statements().getFirst();
        assertThat(statement.vulnerability().name()).isEqualTo("CVE-2023-12345");
        assertThat(statement.status()).isEqualTo(OpenVexDocument.Status.FIXED);
        assertThat(statement.products()).hasSize(1);
        assertThat(statement.products().getFirst().id())
                .isEqualTo("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7");
    }

    @Test
    void shouldParseDocumentWithMultipleStatements() {
        final OpenVexDocument document = parse(/* language=JSON */ """
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

        assertThat(document.statements()).hasSize(2);
        assertThat(document.statements().get(0).status())
                .isEqualTo(OpenVexDocument.Status.UNDER_INVESTIGATION);
        assertThat(document.statements().get(1).products()).hasSize(2);
    }

    @Test
    void shouldParseVulnerabilityWithAliasesAndDescription() {
        final OpenVexDocument document = parse(minimalDoc("""
                "vulnerability": {
                   "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                   "name": "CVE-2021-44228",
                   "description": "Remote code injection in Log4j",
                   "aliases": ["GHSA-jfh8-c2jp-5v3q", "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314721"]
                 },
                 "products": [{"@id": "pkg:apk/wolfi/git@2.39.0-r1"}],
                 "status": "fixed" """));

        final var vulnerability = document.statements().getFirst().vulnerability();
        assertThat(vulnerability.name()).isEqualTo("CVE-2021-44228");
        assertThat(vulnerability.description()).isEqualTo("Remote code injection in Log4j");
        assertThat(vulnerability.aliases()).containsExactly(
                "GHSA-jfh8-c2jp-5v3q", "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314721");
    }

    @Test
    void shouldParseProductWithIdentifiers() {
        final OpenVexDocument document = parse(minimalDoc("""
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

        final var identifiers = document.statements().getFirst().products().getFirst().identifiers();
        assertThat(identifiers.purl()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.4");
        assertThat(identifiers.cpe22()).isEqualTo("cpe:/a:apache:log4j:2.4:-");
        assertThat(identifiers.cpe23()).isEqualTo("cpe:2.3:a:apache:log4j:2.4:-:*:*:*:*:*:*");
    }

    @Test
    void shouldTolerateUnknownFields() {
        final OpenVexDocument document = parse(/* language=JSON */ """
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

        assertThat(document.statements()).hasSize(1);
        assertThat(document.statements().getFirst().actionStatement()).isEqualTo("Upgrade to version 2.40.0");
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
                        "/@context: Required field is missing",
                        "/@id: Required field is missing",
                        "/author: Required field is missing",
                        "/timestamp: Required field is missing",
                        "/version: Required field is missing",
                        "/statements: Required field is missing"));
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
                                .startsWith("/@context: Unsupported OpenVEX specification version")));
    }

    @Test
    void shouldFailForEmptyStatements() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDocWithoutStatements()
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .containsExactly("/statements: Must contain at least one statement"));
    }

    @Test
    void shouldFailForInvalidTimestamp() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDocWithoutStatements()
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
                        .contains("/version: Version must be greater than zero, but was 0"));
    }

    @Test
    void shouldFailForMissingStatus() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}]")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("/statements/0/status: Required field is missing"));
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
                        .contains("/statements/0/status: Unsupported status \"resolved\"; Supported values are "
                                + "[not_affected, affected, fixed, under_investigation]"));
    }

    @Test
    void shouldFailForUnsupportedJustification() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                """
                        "vulnerability": {"name": "CVE-2023-12345"}, \
                        "products": [{"@id": "pkg:x/y@1"}], \
                        "status": "not_affected", \
                        "justification": "code_not_present\"""")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("""
                                /statements/0/justification: Unsupported justification "code_not_present"; \
                                Supported values are [component_not_present, vulnerable_code_not_present, \
                                vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, \
                                inline_mitigations_already_exist]"""
                                .replace("\n", "")));
    }

    @Test
    void shouldFailForNotAffectedWithoutJustificationOrImpactStatement() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"not_affected\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("/statements/0: Either \"justification\" or \"impact_statement\" must be provided "
                                + "when using status \"not_affected\""));
    }

    @Test
    void shouldAcceptNotAffectedWithImpactStatementOnly() {
        final OpenVexDocument document = parse(minimalDoc(
                """
                        "vulnerability": {"name": "CVE-2023-12345"}, \
                        "products": [{"@id": "pkg:x/y@1"}], \
                        "status": "not_affected", \
                        "impact_statement": "Not exploitable as shipped\""""));

        assertThat(document.statements().getFirst().status())
                .isEqualTo(OpenVexDocument.Status.NOT_AFFECTED);
        assertThat(document.statements().getFirst().justification()).isNull();
        assertThat(document.statements().getFirst().impactStatement()).isEqualTo("Not exploitable as shipped");
    }

    @Test
    void shouldFailForAffectedWithoutActionStatement() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"affected\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("/statements/0: \"action_statement\" must be provided when using status \"affected\""));
    }

    @Test
    void shouldFailWhenProductsAreMissingOrEmpty() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {\"name\": \"CVE-2023-12345\"}, \"products\": [], \"status\": \"fixed\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("/statements/0/products: Must contain at least one product"));
    }

    @Test
    void shouldFailForMissingVulnerabilityName() {
        assertThatThrownBy(() -> OpenVexParser.parse(minimalDoc(
                "\"vulnerability\": {}, \"products\": [{\"@id\": \"pkg:x/y@1\"}], \"status\": \"fixed\"")
                .getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(OpenVexParseException.class)
                .satisfies(e -> assertThat(((OpenVexParseException) e).getValidationErrors())
                        .contains("/statements/0/vulnerability/name: Required field is missing"));
    }

    private static OpenVexDocument parse(final String json) {
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
