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

import com.github.packageurl.PackageURL;
import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonReader;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.openvex.model.Identifiers;
import org.dependencytrack.parser.openvex.model.Openvex;
import org.dependencytrack.parser.openvex.model.Statement;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringReader;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.trimToNull;

/**
 * Applies the analyses conveyed by an {@link Openvex} document to existing findings of a project.
 *
 * <p>Analyses can only be applied to vulnerabilities that already exist in Dependency-Track,
 * and only to products that resolve to components of the given project. Statements that cannot
 * be attributed to an unambiguous vulnerability-component pair are skipped. A VEX import must
 * never suppress or alter findings based on unresolved or ambiguous information.
 *
 * <p>When a product declares subcomponents, targets are narrowed down accordingly: Only components
 * that include one of the declared subcomponents as direct dependency (or match one directly)
 * remain targets of the statement.
 *
 * <p>When multiple statements affect the same vulnerability and component pair, statements are
 * applied in chronological order of their timestamps (statements without timestamp first), consistent
 * with the specification's notion of documents being sequences of statements that override and enrich
 * previous ones, and with the reference implementation's handling of out-of-order published statements.
 * The last statement applied wins.
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
     *
     * @param status the status asserted by a {@link Statement}
     */
    static AnalysisState mapStatus(final Statement.Status status) {
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
     * Determines whether an analysis with the given state suppresses the finding.
     * Follows the same policy as CycloneDX VEX imports: {@code FALSE_POSITIVE},
     * {@code NOT_AFFECTED}, and {@code RESOLVED} states are considered suppressed.
     */
    static boolean isSuppressed(final AnalysisState state) {
        return state == AnalysisState.FALSE_POSITIVE
                || state == AnalysisState.NOT_AFFECTED
                || state == AnalysisState.RESOLVED;
    }

    /**
     * Maps OpenVEX justifications to {@link AnalysisJustification}s. Only justifications with an
     * unambiguous Dependency-Track equivalent are mapped. {@code vulnerable_code_cannot_be_controlled_by_adversary}
     * intentionally has no equivalent; why a product is not affected remains preserved through the
     * statement's impact statement.
     *
     * @param justification the justification asserted by a {@link Statement}
     * @return the mapped justification, or {@code null} if there is no equivalent
     */
    static @Nullable AnalysisJustification mapJustification(final Statement.Justification justification) {
        return switch (justification) {
            case COMPONENT_NOT_PRESENT, VULNERABLE_CODE_NOT_PRESENT -> AnalysisJustification.CODE_NOT_PRESENT;
            case VULNERABLE_CODE_NOT_IN_EXECUTE_PATH -> AnalysisJustification.CODE_NOT_REACHABLE;
            case INLINE_MITIGATIONS_ALREADY_EXIST -> AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL;
            case VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY -> {
                LOGGER.debug("""
                        OpenVEX justification "{}" does not have a Dependency-Track equivalent; \
                        Not mapping it""", justification.value());
                yield null;
            }
        };
    }

    public void applyVex(final QueryManager qm, final Openvex document, final Project project) {
        if (document.getStatements().isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any statements; Skipping VEX import");
            return;
        }
        if (!qm.hasVulnerabilities(project)) {
            LOGGER.info("The project {} does not have any vulnerabilities; Skipping VEX import", project);
            return;
        }

        // Statements may be published out of order. Sort them chronologically before applying,
        // so that later verdicts override earlier ones based on when they were issued.
        final List<Statement> sortedStatements = document.getStatements().stream()
                .sorted(Comparator.comparing(OpenVexImporter::timestampOf,
                        Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList();

        final var componentCache = new HashMap<String, List<Component>>();
        for (int statementPosition = 0; statementPosition < sortedStatements.size(); statementPosition++) {
            applyStatement(qm, project, sortedStatements.get(statementPosition), statementPosition, componentCache);
        }
    }

    /**
     * Parses the statement's timestamp for ordering purposes. Returns {@code null} when absent
     * or unparseable, causing the statement to sort (and thus apply) first.
     */
    private static @Nullable OffsetDateTime timestampOf(final Statement statement) {
        if (statement.getTimestamp() == null) {
            return null;
        }

        try {
            return OffsetDateTime.parse(statement.getTimestamp());
        } catch (DateTimeParseException e) {
            LOGGER.debug("""
                    OpenVEX statement timestamp "{}" is not a valid ISO-8601 date-time; \
                    Treating it as timestamp-less""", statement.getTimestamp());
            return null;
        }
    }

    private static void applyStatement(
            final QueryManager qm,
            final Project project,
            final Statement statement,
            final int statementPosition,
            final Map<String, List<Component>> componentCache) {
        if (statement.getProducts().isEmpty()) {
            // The products array is optional per specification. Without it, the statement does
            // not convey which components it applies to, and no analysis can be made.
            LOGGER.debug("""
                    OpenVEX statement #{} does not declare any products; Skipping it""", statementPosition);
            return;
        }

        final Vulnerability vulnerability = resolveVulnerability(qm, statement, statementPosition);
        if (vulnerability == null) {
            return;
        }

        final AnalysisState state = mapStatus(statement.getStatus());

        // Justifications qualify analyses of "not_affected" states. For any other status they
        // would contradict the state they accompany, so they are deliberately not applied.
        final AnalysisJustification justification =
                state == AnalysisState.NOT_AFFECTED && statement.getJustification() != null
                        ? mapJustification(statement.getJustification())
                        : null;

        final var details = detailsOf(statement);

        for (int productPosition = 0; productPosition < statement.getProducts().size(); productPosition++) {
            final org.dependencytrack.parser.openvex.model.Component product = statement.getProducts().get(productPosition);

            final List<Component> productComponents = resolveComponents(qm, project, product, componentCache);
            if (productComponents.isEmpty()) {
                LOGGER.warn("""
                        Unable to locate a component matching the product at position #{} of OpenVEX statement \
                        #{} ({}); Skipping it""", productPosition, statementPosition, describe(product));
                continue;
            }

            final List<Component> targetComponents = product.getSubcomponents().isEmpty()
                    ? productComponents
                    : narrowBySubcomponents(
                            qm, project, product, productComponents, componentCache,
                            statementPosition, productPosition);
            if (targetComponents.isEmpty()) {
                // Reason is logged where the components are narrowed down.
                continue;
            }

            for (final Component component : targetComponents) {
                MakeAnalysisCommand command = new MakeAnalysisCommand(component, vulnerability)
                        .withCommenter(COMMENTER)
                        .withState(state)
                        .withSuppress(isSuppressed(state));
                if (justification != null) {
                    command = command.withJustification(justification);
                }
                if (details != null) {
                    command = command.withDetails(details);
                }

                qm.makeAnalysis(command);
            }
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
        candidateIds.add(statement.getVulnerability().getName());
        candidateIds.addAll(statement.getVulnerability().getAliases());

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
                    statementPosition, statement.getVulnerability().getName());
            return null;
        }
        if (candidates.size() > 1) {
            // Multiple distinct candidates mean that name and aliases identify different
            // vulnerabilities. Guessing either one would be wrong.
            LOGGER.warn("""
                    OpenVEX statement #{} references vulnerability {}, whose name and aliases identify multiple \
                    distinct vulnerabilities ({}); Skipping it""", statementPosition,
                    statement.getVulnerability().getName(),
                    candidates.stream()
                            .map(vuln -> "%s/%s".formatted(vuln.getSource(), vuln.getVulnId()))
                            .toList());
            return null;
        }

        return candidates.getFirst();
    }

    /**
     * Resolves a product or subcomponent to components of the given project using its purl,
     * respectively CPE identifier, in this order of precedence. Components identified by other
     * means (such as hashes only) cannot be matched reliably and are reported as unresolved.
     *
     * <p>Results are memoized in {@code componentCache}, keyed by the identifying properties,
     * so identical identities are only matched against the database once.
     */
    private static List<Component> resolveComponents(
            final QueryManager qm,
            final Project project,
            final org.dependencytrack.parser.openvex.model.Component component,
            final Map<String, List<Component>> componentCache) {
        return resolveComponents(qm, project, component.getId(), component.getIdentifiers(), componentCache);
    }

    private static List<Component> resolveComponents(
            final QueryManager qm,
            final Project project,
            final @Nullable String id,
            final @Nullable Identifiers identifiers,
            final Map<String, List<Component>> componentCache) {
        final @Nullable String cpe23 = identifiers != null ? trimToNull(identifiers.getCpe23()) : null;
        final @Nullable String cpe22 = identifiers != null ? trimToNull(identifiers.getCpe22()) : null;
        final @Nullable PackageURL purl = purlOf(id, identifiers);

        if (purl == null && cpe23 == null && cpe22 == null) {
            return List.of();
        }

        // The cache key captures all inputs of identity matching, so identities with equal keys
        // are guaranteed to resolve to the same components.
        return componentCache.computeIfAbsent(
                "%s|%s|%s".formatted(purl, cpe23, cpe22),
                _ -> matchComponents(qm, project, purl, cpe23, cpe22));
    }

    /**
     * Determines the purl identifying a product or subcomponent, considering both the
     * {@code identifiers} and the {@code @id} field, which per specification may take a purl as value.
     */
    private static @Nullable PackageURL purlOf(
            final @Nullable String id,
            final @Nullable Identifiers identifiers) {
        if (identifiers != null) {
            final PackageURL purl = PurlUtil.silentPurl(trimToNull(identifiers.getPurl()));
            if (purl != null) {
                return purl;
            }
        }

        if (id != null && id.startsWith("pkg:")) {
            return PurlUtil.silentPurl(id);
        }

        return null;
    }

    private static List<Component> matchComponents(
            final QueryManager qm,
            final Project project,
            final @Nullable PackageURL purl,
            final @Nullable String cpe23,
            final @Nullable String cpe22) {
        if (purl != null) {
            // Align with the stricter PURL comparison of the openvex/go-vex reference
            // implementation: qualifiers and version must match exactly, so over-broad
            // matches are filtered out before any analysis state is applied.
            final List<Component> matches = qm.matchIdentity(
                            project, new ComponentIdentity(purl, null, null, null, null, null))
                    .stream()
                    .filter(component -> purlEquals(purl, component.getPurl()))
                    .toList();
            if (!matches.isEmpty()) {
                return matches;
            }
        }

        for (final String cpe : Stream.of(cpe23, cpe22).filter(cpe -> !isBlank(cpe)).toList()) {
            final List<Component> matches =
                    qm.matchIdentity(project, new ComponentIdentity(null, cpe, null, null, null, null));
            if (!matches.isEmpty()) {
                return matches;
            }
        }

        return List.of();
    }

    /**
     * Structurally compares the given purls, following the matching rules of the
     * <a href="https://github.com/openvex/go-vex/blob/main/pkg/vex/vex.go">go-vex reference
     * implementation</a>: type, namespace, name, version, and qualifiers must all be equal.
     */
    private static boolean purlEquals(final PackageURL expected, final @Nullable PackageURL actual) {
        if (actual == null) {
            return false;
        }

        return Objects.equals(expected.getType(), actual.getType())
                && Objects.equals(expected.getNamespace(), actual.getNamespace())
                && Objects.equals(expected.getName(), actual.getName())
                && Objects.equals(expected.getVersion(), actual.getVersion())
                && Objects.equals(expected.getQualifiers(), actual.getQualifiers());
    }

    /**
     * Narrows the components a product resolved to, based on the subcomponents declared for it.
     * Per specification, subcomponents describe the components included in the product where the
     * vulnerability originates. A component remains a target if it matches one of the declared
     * subcomponents directly, or includes one as direct dependency.
     *
     * @return the components to apply the statement to. Guaranteed to be non-empty; when no
     *         targets remain, the reason is logged and an empty list is returned.
     */
    private static List<Component> narrowBySubcomponents(
            final QueryManager qm,
            final Project project,
            final org.dependencytrack.parser.openvex.model.Component product,
            final List<Component> productComponents,
            final Map<String, List<Component>> componentCache,
            final int statementPosition,
            final int productPosition) {
        final var matchedSubcomponentUuids = new HashSet<String>();
        final var unmatchedPositions = new ArrayList<Integer>();
        for (int subcomponentPosition = 0; subcomponentPosition < product.getSubcomponents().size(); subcomponentPosition++) {
            final org.dependencytrack.parser.openvex.model.Component subcomponent =
                    product.getSubcomponents().get(subcomponentPosition);

            final List<Component> matches = resolveComponents(qm, project, subcomponent, componentCache);
            if (matches.isEmpty()) {
                unmatchedPositions.add(subcomponentPosition);
                continue;
            }

            matches.forEach(match -> matchedSubcomponentUuids.add(match.getUuid().toString()));
        }

        if (matchedSubcomponentUuids.isEmpty()) {
            LOGGER.warn("""
                    OpenVEX statement #{} declares {} subcomponent(s) for its product at position #{}, \
                    none of which match any component of the project (unresolved at positions [{}]); \
                    Skipping the product""", statementPosition, product.getSubcomponents().size(),
                    productPosition, String.join(", ",
                            unmatchedPositions.stream().map(String::valueOf).toList()));
            return List.of();
        }

        final List<Component> targetComponents = productComponents.stream()
                .filter(component -> matchedSubcomponentUuids.contains(component.getUuid().toString())
                        || hasDirectDependencyWithUuid(component, matchedSubcomponentUuids))
                .toList();
        if (targetComponents.isEmpty()) {
            LOGGER.warn("""
                    None of the components matching the product at position #{} of OpenVEX statement #{} \
                    includes any of its {} declared subcomponent(s); Skipping the product""",
                    productPosition, statementPosition, product.getSubcomponents().size());
        }

        return targetComponents;
    }

    /**
     * Determines whether the given component declares any of the components identified by the
     * given UUIDs as direct dependency.
     */
    private static boolean hasDirectDependencyWithUuid(final Component component, final Set<String> uuids) {
        if (isBlank(component.getDirectDependencies())) {
            return false;
        }

        try (final JsonReader jsonReader = Json.createReader(new StringReader(component.getDirectDependencies()))) {
            return jsonReader.readArray().stream()
                    .map(value -> value.asJsonObject().getString("uuid"))
                    .anyMatch(uuids::contains);
        } catch (JsonException e) {
            LOGGER.debug("Failed to parse the direct dependencies of component {}",
                    component.getUuid(), e);
            return false;
        }
    }

    /**
     * Combines impact statement, action statement, and status notes into analysis details.
     * All are free-form texts explaining the asserted status; Dependency-Track has a single
     * details field for them.
     */
    private static @Nullable String detailsOf(final Statement statement) {
        final var details = Stream.of(
                        statement.getImpactStatement(),
                        statement.getActionStatement(),
                        statement.getStatusNotes())
                .filter(text -> !isBlank(text))
                .toList();
        return details.isEmpty() ? null : String.join("\n\n", details);
    }

    private static String describe(final org.dependencytrack.parser.openvex.model.Component component) {
        if (component.getIdentifiers() != null && !isBlank(component.getIdentifiers().getPurl())) {
            return component.getIdentifiers().getPurl();
        } else if (component.getId() != null) {
            return component.getId();
        } else if (component.getIdentifiers() != null && !isBlank(component.getIdentifiers().getCpe23())) {
            return component.getIdentifiers().getCpe23();
        } else if (component.getIdentifiers() != null && !isBlank(component.getIdentifiers().getCpe22())) {
            return component.getIdentifiers().getCpe22();
        }
        return "no usable identifier provided";
    }

}
