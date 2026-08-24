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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.openvex.OpenVexDocument.Justification;
import org.dependencytrack.parser.openvex.OpenVexDocument.Product;
import org.dependencytrack.parser.openvex.OpenVexDocument.Statement;
import org.dependencytrack.parser.openvex.OpenVexDocument.Status;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Applies the analyses conveyed by an {@link OpenVexDocument} to existing findings of a project.
 *
 * <p>Analyses can only be applied to vulnerabilities that already exist in Dependency-Track,
 * and only to products that resolve to components of the given project. Statements that cannot
 * be attributed to an unambiguous vulnerability-component pair are skipped. A VEX import must
 * never suppress or alter findings based on unresolved or ambiguous information.
 *
 * <p>When multiple statements affect the same vulnerability and component pair, statements are
 * applied in document order; the last statement wins, consistent with the specification's notion
 * of documents being sequences of statements that override and enrich previous ones.
 *
 * @see <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md">OpenVEX Specification</a>
 * @since 5.7.0
 */
public class OpenVexImporter {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenVexImporter.class);

    private static final String COMMENTER = "OpenVEX";

    /**
     * Maps OpenVEX statuses to {@link AnalysisState}s. Every status defined by the specification
     * has a mapping; none are left unsupported.
     */
    private static AnalysisState mapStatus(final Status status) {
        return switch (status) {
            case NOT_AFFECTED -> AnalysisState.NOT_AFFECTED;
            case AFFECTED ->
                    // "Actions are recommended to remediate or address this vulnerability".
                    // EXPLOITABLE is Dependency-Track's only state expressing active impact.
                    AnalysisState.EXPLOITABLE;
            case FIXED -> AnalysisState.RESOLVED;
            case UNDER_INVESTIGATION -> AnalysisState.IN_TRIAGE;
        };
    }

    /**
     * Maps OpenVEX justifications to {@link AnalysisJustification}s. Only justifications with an
     * unambiguous Dependency-Track equivalent are mapped. {@code vulnerable_code_cannot_be_controlled_by_adversary}
     * intentionally has no equivalent; why a product is not affected remains preserved through the
     * statement's impact statement.
     */
    private static @Nullable AnalysisJustification mapJustification(final Justification justification) {
        return switch (justification) {
            case COMPONENT_NOT_PRESENT, VULNERABLE_CODE_NOT_PRESENT -> AnalysisJustification.CODE_NOT_PRESENT;
            case VULNERABLE_CODE_NOT_IN_EXECUTE_PATH -> AnalysisJustification.CODE_NOT_REACHABLE;
            case INLINE_MITIGATIONS_ALREADY_EXIST -> AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL;
            case VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY -> {
                LOGGER.debug("""
                        OpenVEX justification "%s" does not have a Dependency-Track equivalent; \
                        Not mapping it""".formatted(justification.getLabel()));
                yield null;
            }
        };
    }

    public void applyVex(final QueryManager qm, final OpenVexDocument document, final Project project) {
        if (document.statements().isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any statements; Skipping VEX import");
            return;
        }
        if (!qm.hasVulnerabilities(project)) {
            LOGGER.info("The project {} does not have any vulnerabilities; Skipping VEX import", project);
            return;
        }

        int statementPosition = 0;
        for (final Statement statement : document.statements()) {
            applyStatement(qm, project, statement, statementPosition++);
        }
    }

    private static void applyStatement(
            final QueryManager qm,
            final Project project,
            final Statement statement,
            final int statementPosition) {
        final Vulnerability vulnerability = resolveVulnerability(qm, statement, statementPosition);
        if (vulnerability == null) {
            return;
        }

        final AnalysisState state = mapStatus(statement.status());
        final boolean isSuppressed =
                state == AnalysisState.FALSE_POSITIVE
                        || state == AnalysisState.NOT_AFFECTED
                        || state == AnalysisState.RESOLVED;

        // Justifications qualify analyses of "not_affected" states. For any other status they
        // would contradict the state they accompany, so they are deliberately not applied.
        final AnalysisJustification justification =
                state == AnalysisState.NOT_AFFECTED && statement.justification() != null
                        ? mapJustification(statement.justification())
                        : null;

        final var details = detailsOf(statement);

        int productPosition = 0;
        for (final Product product : statement.products()) {
            if (!product.subcomponents().isEmpty()) {
                LOGGER.debug("""
                        OpenVEX statement #{} declares {} subcomponent(s) for its product at position #{}; \
                        Subcomponents are informational, and will not be evaluated""",
                        statementPosition, product.subcomponents().size(), productPosition);
            }

            final List<Component> components = resolveComponents(qm, project, product);
            if (components.isEmpty()) {
                LOGGER.warn("""
                        Unable to locate a component matching the product at position #{} of OpenVEX statement \
                        #{} ({}); Skipping it""", productPosition, statementPosition, describe(product));
                continue;
            }

            for (final Component component : components) {
                MakeAnalysisCommand command = new MakeAnalysisCommand(component, vulnerability)
                        .withCommenter(COMMENTER)
                        .withState(state)
                        .withSuppress(isSuppressed);
                if (justification != null) {
                    command = command.withJustification(justification);
                }
                if (details != null) {
                    command = command.withDetails(details);
                }

                qm.makeAnalysis(command);
            }

            productPosition++;
        }
    }

    /**
     * Resolves the vulnerability referenced by a statement against vulnerabilities known to
     * Dependency-Track. Both the vulnerability name and its aliases are considered as candidate
     * identifiers. Returns {@code null}, logging the reason, when the reference cannot be attributed
     * to exactly one vulnerability.
     */
    private static @Nullable Vulnerability resolveVulnerability(
            final QueryManager qm,
            final Statement statement,
            final int statementPosition) {
        // OpenVEX does not convey which source a vulnerability identifier belongs to.
        // Candidate identifiers are therefore resolved by ID alone, in order of precedence:
        // name first, then aliases.
        final var candidateIds = new LinkedHashSet<String>();
        candidateIds.add(statement.vulnerability().name());
        candidateIds.addAll(statement.vulnerability().aliases());

        final var candidates = new LinkedHashSet<Vulnerability>();
        for (final String candidateId : candidateIds) {
            final List<Vulnerability> matches = qm.getVulnerabilitiesByVulnId(candidateId);
            if (matches.isEmpty()) {
                continue;
            }
            if (matches.size() > 1) {
                LOGGER.warn("""
                        OpenVEX statement #{} references vulnerability {}, which alone matches vulnerabilities \
                        from multiple sources ({}); Skipping it""", statementPosition, candidateId,
                        matches.stream().map(Vulnerability::getSource).toList());
                return null;
            }

            candidates.add(matches.getFirst());
        }

        if (candidates.isEmpty()) {
            LOGGER.warn("""
                    OpenVEX statement #{} contains an analysis for vulnerability {}, but the project is not \
                    affected by it. Analyses can currently only be applied to existing findings; Skipping it""",
                    statementPosition, statement.vulnerability().name());
            return null;
        }
        if (candidates.size() > 1) {
            // Multiple distinct candidates mean that name and aliases identify different
            // vulnerabilities. Guessing either one would be wrong.
            LOGGER.warn("""
                    OpenVEX statement #{} references vulnerability {}, whose name and aliases identify multiple \
                    distinct vulnerabilities ({}); Skipping it""", statementPosition,
                    statement.vulnerability().name(),
                    candidates.stream()
                            .map(vuln -> "%s/%s".formatted(vuln.getSource(), vuln.getVulnId()))
                            .toList());
            return null;
        }

        return candidates.getFirst();
    }

    /**
     * Resolves a product to components of the given project using its purl, respectively CPE
     * identifier, in this order of precedence. Products identified by other means (such as hashes
     * only) cannot be matched reliably and are reported as unresolved.
     *
     * <p>Matching reuses {@link QueryManager#matchIdentity(Project, ComponentIdentity)}. Identities
     * constructed here carry no group/name/version coordinates. Because component names can never
     * be {@code null}, the coordinate-matching clause of {@code matchIdentity} can never match any
     * persisted component for such identities, making the result equivalent to an exact purl or
     * CPE lookup within the project.
     */
    private static List<Component> resolveComponents(final QueryManager qm, final Project project, final Product product) {
        final var identitiesToMatch = new ArrayList<ComponentIdentity>();

        var purl = parsePurl(product.identifiers() != null ? product.identifiers().purl() : null);
        if (purl == null && product.id() != null && product.id().startsWith("pkg:")) {
            // Per specification, "@id" may take a purl as value.
            purl = parsePurl(product.id());
        }
        if (purl != null) {
            identitiesToMatch.add(new ComponentIdentity(purl, null, null, null, null, null));
        }

        if (product.identifiers() != null) {
            Stream.of(product.identifiers().cpe23(), product.identifiers().cpe22())
                    .filter(cpe -> !isBlank(cpe))
                    .forEach(cpe -> identitiesToMatch.add(new ComponentIdentity(null, cpe, null, null, null, null)));
        }

        for (final ComponentIdentity identity : identitiesToMatch) {
            final List<Component> matches = qm.matchIdentity(project, identity);
            if (!matches.isEmpty()) {
                return matches;
            }
        }

        return List.of();
    }

    private static @Nullable PackageURL parsePurl(final @Nullable String purlString) {
        if (isBlank(purlString)) {
            return null;
        }

        try {
            return new PackageURL(purlString);
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Failed to parse \"{}\" as purl", purlString, e);
            return null;
        }
    }

    /**
     * Combines impact and action statements into analysis details. Both are free-form texts
     * explaining the asserted status; Dependency-Track has a single details field for them.
     */
    private static @Nullable String detailsOf(final Statement statement) {
        final var details = Stream.of(statement.impactStatement(), statement.actionStatement())
                .filter(text -> !isBlank(text))
                .collect(Collectors.toList());
        return details.isEmpty() ? null : String.join("\n", details);
    }

    private static String describe(final Product product) {
        if (product.identifiers() != null && product.identifiers().purl() != null) {
            return product.identifiers().purl();
        } else if (product.id() != null) {
            return product.id();
        }
        return "no usable identifier provided";
    }

}
