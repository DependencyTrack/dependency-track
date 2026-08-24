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

import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Representation of an <a href="https://openvex.dev/">OpenVEX</a> document as defined by version 0.2.0
 * of the <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md">OpenVEX Specification</a>.
 * <p>
 * Instances of this record are only created by {@link OpenVexParser}, which guarantees that required
 * fields are present, and that vocabularies are limited to the values defined by the specification.
 *
 * @param context    the JSON-LD context of the document ({@code @context} field)
 * @param id         IRI identifying the document ({@code @id} field)
 * @param author     identifier of the document's author
 * @param role       role of the document's author, or {@code null} when not provided
 * @param timestamp  time at which the document was issued, in ISO-8601 format
 * @param version    version of the document
 * @param tooling    tooling used to generate the document, or {@code null} when not provided
 * @param statements statements made by this document
 * @since 5.7.0
 */
public record OpenVexDocument(
        String context,
        String id,
        String author,
        @Nullable String role,
        String timestamp,
        int version,
        @Nullable String tooling,
        List<Statement> statements) {

    private static final Pattern SPEC_VERSION_PATTERN = Pattern.compile("^https://openvex\\.dev/ns/v(\\d+\\.\\d+\\.\\d+)$");

    /**
     * The specification version this document conforms to, derived from its JSON-LD context.
     * For example, a context of {@code https://openvex.dev/ns/v0.2.0} yields {@code 0.2.0}.
     *
     * @return the specification version, or {@code null} if it cannot be derived from the context
     */
    public @Nullable String specVersion() {
        if (context == null) {
            return null;
        }
        final var matcher = SPEC_VERSION_PATTERN.matcher(context);
        return matcher.matches() ? matcher.group(1) : null;
    }

    /**
     * A statement asserting the impact {@link Status} of one {@link Vulnerability} on one or more {@link Product}s.
     *
     * @param vulnerability   the vulnerability the statement is about
     * @param products        the products the statement applies to
     * @param status          the impact status asserted by the statement
     * @param justification   machine-readable reason for the {@link Status#NOT_AFFECTED} status,
     *                        or {@code null} when not provided
     * @param impactStatement free-form text explaining why a product is not affected,
     *                        or {@code null} when not provided
     * @param actionStatement free-form text describing actions to remediate or mitigate the vulnerability
     *                        for the {@link Status#AFFECTED} status, or {@code null} when not provided
     */
    public record Statement(
            Vulnerability vulnerability,
            List<Product> products,
            Status status,
            @Nullable Justification justification,
            @Nullable String impactStatement,
            @Nullable String actionStatement) {
    }

    /**
     * A cataloged defect in a software product.
     *
     * @param name        main identifier of the vulnerability, e.g. {@code CVE-2021-44228}
     * @param description description of the vulnerability, or {@code null} when not provided
     * @param aliases     other identifiers under which the vulnerability may be known
     */
    public record Vulnerability(
            String name,
            @Nullable String description,
            List<String> aliases) {

        public Vulnerability {
            aliases = aliases == null ? List.of() : List.copyOf(aliases);
        }
    }

    /**
     * A logical unit representing a piece of software.
     * <p>
     * Cryptographic hashes declared for a product are not represented, as they cannot be used
     * to match components in Dependency-Track.
     *
     * @param id            IRI identifying the product, often a Package URL, or {@code null} when not provided
     * @param identifiers   additional software identifiers, or {@code null} when not provided
     * @param subcomponents components included in the product where the vulnerability originates.
     *                      Informational only; not evaluated during import.
     */
    public record Product(
            @Nullable String id,
            @Nullable Identifiers identifiers,
            List<Component> subcomponents) {

        public Product {
            subcomponents = subcomponents == null ? List.of() : List.copyOf(subcomponents);
        }
    }

    /**
     * Fields shared by products and subcomponents.
     *
     * @param id          IRI identifying the component, or {@code null} when not provided
     * @param identifiers additional software identifiers, or {@code null} when not provided
     */
    public record Component(
            @Nullable String id,
            @Nullable Identifiers identifiers) {
    }

    /**
     * Map of software identifiers, as used by products and subcomponents.
     *
     * @param purl  Package URL, or {@code null} when not provided
     * @param cpe22 CPE 2.2 identifier, or {@code null} when not provided
     * @param cpe23 CPE 2.3 identifier, or {@code null} when not provided
     */
    public record Identifiers(
            @Nullable String purl,
            @Nullable String cpe22,
            @Nullable String cpe23) {
    }

    /**
     * Impact statuses as defined by the VEX working group.
     *
     * @see <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels">OpenVEX Specification</a>
     */
    public enum Status {

        NOT_AFFECTED("not_affected"),
        AFFECTED("affected"),
        FIXED("fixed"),
        UNDER_INVESTIGATION("under_investigation");

        private final String label;

        Status(final String label) {
            this.label = label;
        }

        /**
         * The label of this status as used in OpenVEX documents.
         */
        public String getLabel() {
            return label;
        }

        public static Optional<Status> fromLabel(final String label) {
            for (final Status status : values()) {
                if (status.label.equals(label)) {
                    return Optional.of(status);
                }
            }
            return Optional.empty();
        }
    }

    /**
     * Status justifications as defined by the VEX working group.
     *
     * @see <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications">OpenVEX Specification</a>
     */
    public enum Justification {

        COMPONENT_NOT_PRESENT("component_not_present"),
        VULNERABLE_CODE_NOT_PRESENT("vulnerable_code_not_present"),
        VULNERABLE_CODE_NOT_IN_EXECUTE_PATH("vulnerable_code_not_in_execute_path"),
        VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY("vulnerable_code_cannot_be_controlled_by_adversary"),
        INLINE_MITIGATIONS_ALREADY_EXIST("inline_mitigations_already_exist");

        private final String label;

        Justification(final String label) {
            this.label = label;
        }

        /**
         * The label of this justification as used in OpenVEX documents.
         */
        public String getLabel() {
            return label;
        }

        public static Optional<Justification> fromLabel(final String label) {
            for (final Justification justification : values()) {
                if (justification.label.equals(label)) {
                    return Optional.of(justification);
                }
            }
            return Optional.empty();
        }
    }
}
