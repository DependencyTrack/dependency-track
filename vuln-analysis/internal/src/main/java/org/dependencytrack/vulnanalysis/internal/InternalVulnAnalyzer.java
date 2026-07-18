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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.version.KnownVersioningSchemes;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.support.distrometadata.OsDistribution;
import org.dependencytrack.support.jdbi.exception.TransientSqlErrors;
import org.dependencytrack.vulnanalysis.api.RetryableVulnAnalysisException;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.internal.Coordinate.CpeCoordinate;
import org.dependencytrack.vulnanalysis.internal.Coordinate.PurlCoordinate;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.util.Relation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Gatherers;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_GENERIC;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class InternalVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(InternalVulnAnalyzer.class);
    private static final Pattern EPOCH_PREFIX_PATTERN = Pattern.compile("^\\d+:");
    private static final String INTERNAL_VULN_ID_PROPERTY = "dependencytrack:internal:vulnerability-id";
    private static final int QUERY_BATCH_SIZE = 25;

    private final Jdbi jdbi;

    InternalVulnAnalyzer(Jdbi jdbi) {
        this.jdbi = jdbi;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        final var candidates = new ArrayList<CandidateComponent>();
        collectScannableComponents(bom.getComponentsList(), candidates);

        if (candidates.isEmpty()) {
            return Bom.getDefaultInstance();
        }

        final var candidatesByCoordinate = new HashMap<Coordinate, Set<CandidateComponent>>();

        for (final CandidateComponent candidate : candidates) {
            for (final Coordinate coordinate : Coordinate.of(candidate)) {
                candidatesByCoordinate.computeIfAbsent(coordinate, k -> new HashSet<>()).add(candidate);
            }
        }

        final var cpeCoordinates = new ArrayList<CpeCoordinate>();
        final var purlCoordinates = new ArrayList<PurlCoordinate>();
        for (final Coordinate coordinate : candidatesByCoordinate.keySet()) {
            switch (coordinate) {
                case CpeCoordinate it -> cpeCoordinates.add(it);
                case PurlCoordinate it -> purlCoordinates.add(it);
            }
        }

        final var findingsByVuln = new HashMap<Long, Set<Long>>();
        final var vulnMetadata = new HashMap<Long, VulnMetadata>();

        for (final var batch : (Iterable<List<CpeCoordinate>>) () -> cpeCoordinates.stream()
                .gather(Gatherers.windowFixed(QUERY_BATCH_SIZE))
                .iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            LOGGER.debug("Querying matching criteria for {} CPE coordinates", batch.size());
            processCriteria(
                    queryCpeMatchingCriteria(batch),
                    candidatesByCoordinate,
                    findingsByVuln,
                    vulnMetadata);
        }

        for (final var batch : (Iterable<List<PurlCoordinate>>) () -> purlCoordinates.stream()
                .gather(Gatherers.windowFixed(QUERY_BATCH_SIZE))
                .iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be analyzed");
            }

            LOGGER.debug("Querying matching criteria for {} PURL coordinates", batch.size());
            processCriteria(
                    queryPurlMatchingCriteria(batch),
                    candidatesByCoordinate,
                    findingsByVuln,
                    vulnMetadata);
        }

        final var vulnerabilities = new ArrayList<Vulnerability>();
        for (final Map.Entry<Long, Set<Long>> entry : findingsByVuln.entrySet()) {
            final Long vulnDbId = entry.getKey();
            final Set<Long> affectedComponentIds = entry.getValue();
            final VulnMetadata metadata = vulnMetadata.get(vulnDbId);

            final var vulnBuilder = Vulnerability.newBuilder()
                    .setId(metadata.vulnId())
                    .setSource(Source.newBuilder().setName(metadata.source()))
                    .addProperties(Property.newBuilder()
                            .setName(INTERNAL_VULN_ID_PROPERTY)
                            .setValue(String.valueOf(vulnDbId)));

            for (final Long componentId : affectedComponentIds) {
                vulnBuilder
                        .addAffects(VulnerabilityAffects.newBuilder()
                                .setRef(String.valueOf(componentId)));
            }

            vulnerabilities.add(vulnBuilder.build());
        }

        return Bom.newBuilder()
                .addAllVulnerabilities(vulnerabilities)
                .build();
    }

    private Map<Coordinate, List<MatchingCriteria>> queryCpeMatchingCriteria(List<CpeCoordinate> coordinates) {
        // Assemble multiple queries and join their results using UNION.
        // This ensures that the database is able to leverage indexes properly,
        // which use of OR can prevent from happening: https://dba.stackexchange.com/a/293838
        //
        // i.e., what usually would've been:
        //   SELECT ... WHERE ("PART" = '*' OR "PART" = 'foo') ...
        // now becomes:
        //   SELECT ... WHERE "PART" = '*' ...
        //   UNION
        //   SELECT ... WHERE "PART" = 'foo' ...
        final var queryBranches = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();
        int queryConditionIdx = 0;

        for (int coordinateIdx = 0; coordinateIdx < coordinates.size(); coordinateIdx++) {
            final CpeCoordinate coordinate = coordinates.get(coordinateIdx);
            for (final var partCondition : CpeFilterCondition.of(CpeAttribute.PART, coordinate.part())) {
                for (final var vendorCondition : CpeFilterCondition.of(CpeAttribute.VENDOR, coordinate.vendor())) {
                    for (final var productCondition : CpeFilterCondition.of(CpeAttribute.PRODUCT, coordinate.product())) {
                        final int idx = queryConditionIdx++;
                        final var partParam = "part" + idx;
                        final var vendorParam = "vendor" + idx;
                        final var productParam = "product" + idx;

                        queryBranches.add(/* language=SQL */ """
                                SELECT "ID" AS vs_id
                                     , %d AS coordinate_index
                                  FROM "VULNERABLESOFTWARE"
                                 WHERE %s
                                   AND %s
                                   AND %s\
                                """.formatted(
                                coordinateIdx,
                                partCondition.toSql(partParam),
                                vendorCondition.toSql(vendorParam),
                                productCondition.toSql(productParam)));
                        if (partCondition.value() != null) {
                            queryParams.put(partParam, partCondition.value());
                        }
                        if (vendorCondition.value() != null) {
                            queryParams.put(vendorParam, vendorCondition.value());
                        }
                        if (productCondition.value() != null) {
                            queryParams.put(productParam, productCondition.value());
                        }
                    }
                }
            }
        }

        return queryMatchingCriteria(
                String.join("\nUNION ALL\n", queryBranches),
                query -> query.bindMap(queryParams),
                coordinates);
    }

    private Map<Coordinate, List<MatchingCriteria>> queryPurlMatchingCriteria(List<PurlCoordinate> coordinates) {
        // PURL namespace is nullable, and the naive `"PURL_NAMESPACE" IS NOT DISTINCT FROM ?`
        // can't use BTree indexes. Postgres 18 shipped with Skip Scans which still leads to
        // an index to be leveraged, but still in a suboptimal way.
        //
        // To combat this, we use a UNION query that branches on whether the coordinates
        // have a `null` namespace. This allows explicit usage of `IS NULL` and `=`,
        // which the query planner can use reliably for index scans.
        //
        // On contrast to the more complex CPE queries, the query branches here
        // are still batched.

        final var nsTypes = new ArrayList<String>();
        final var namespaces = new ArrayList<String>();
        final var nsNames = new ArrayList<String>();
        final var nsIndexes = new ArrayList<Integer>();

        final var nullNsTypes = new ArrayList<String>();
        final var nullNsNames = new ArrayList<String>();
        final var nullNsIndexes = new ArrayList<Integer>();

        for (int i = 0; i < coordinates.size(); i++) {
            final PurlCoordinate coordinate = coordinates.get(i);
            if (coordinate.namespace() != null) {
                nsTypes.add(coordinate.type());
                namespaces.add(coordinate.namespace());
                nsNames.add(coordinate.name());
                nsIndexes.add(i);
            } else {
                nullNsTypes.add(coordinate.type());
                nullNsNames.add(coordinate.name());
                nullNsIndexes.add(i);
            }
        }

        final var queryBranches = new ArrayList<String>(2);

        if (!nullNsIndexes.isEmpty()) {
            queryBranches.add(/* language=SQL */ """
                    SELECT vs."ID" AS vs_id
                         , t.idx AS coordinate_index
                      FROM UNNEST(:nullNsTypes, :nullNsNames, :nullNsIndexes)
                        AS t(purl_type, purl_name, idx)
                     INNER JOIN "VULNERABLESOFTWARE" AS vs
                        ON vs."PURL_TYPE" = t.purl_type
                       AND vs."PURL_NAMESPACE" IS NULL
                       AND vs."PURL_NAME" = t.purl_name\
                    """);
        }

        if (!nsIndexes.isEmpty()) {
            queryBranches.add(/* language=SQL */ """
                    SELECT vs."ID" AS vs_id
                         , t.idx AS coordinate_index
                      FROM UNNEST(:nsTypes, :nsNamespaces, :nsNames, :nsIndexes)
                        AS t(purl_type, purl_namespace, purl_name, idx)
                     INNER JOIN "VULNERABLESOFTWARE" AS vs
                        ON vs."PURL_TYPE" = t.purl_type
                       AND vs."PURL_NAMESPACE" = t.purl_namespace
                       AND vs."PURL_NAME" = t.purl_name\
                    """);
        }

        return queryMatchingCriteria(
                String.join("\nUNION ALL\n", queryBranches),
                query -> {
                    if (!nullNsIndexes.isEmpty()) {
                        query
                                .bind("nullNsTypes", nullNsTypes.toArray(String[]::new))
                                .bind("nullNsNames", nullNsNames.toArray(String[]::new))
                                .bind("nullNsIndexes", nullNsIndexes.stream().mapToInt(Integer::intValue).toArray());
                    }
                    if (!nsIndexes.isEmpty()) {
                        query
                                .bind("nsTypes", nsTypes.toArray(String[]::new))
                                .bind("nsNamespaces", namespaces.toArray(String[]::new))
                                .bind("nsNames", nsNames.toArray(String[]::new))
                                .bind("nsIndexes", nsIndexes.stream().mapToInt(Integer::intValue).toArray());
                    }
                },
                coordinates);
    }

    private Map<Coordinate, List<MatchingCriteria>> queryMatchingCriteria(
            String innerSql,
            Consumer<Query> binder,
            List<? extends Coordinate> coordinates) {
        final String sql = /* language=SQL */ """
                SELECT vs.*
                     , v."ID" AS vuln_db_id
                     , v."VULNID" AS vuln_id
                     , v."SOURCE" AS vuln_source
                     , m.coordinate_index
                  FROM (%s) AS m
                 INNER JOIN "VULNERABLESOFTWARE" AS vs
                    ON vs."ID" = m.vs_id
                 INNER JOIN "VULNERABLESOFTWARE_VULNERABILITIES" AS vsv
                    ON vsv."VULNERABLESOFTWARE_ID" = vs."ID"
                 INNER JOIN "VULNERABILITY" AS v
                    ON v."ID" = vsv."VULNERABILITY_ID"
                   AND v."REJECTED" IS NULL
                """.formatted(innerSql);

        try {
            return jdbi.withHandle(handle -> {
                final Query query = handle.createQuery(sql);
                binder.accept(query);
                return query
                        .mapTo(MatchingCriteria.class)
                        .collect(Collectors.groupingBy(
                                criteria -> coordinates.get(criteria.coordinateIndex())));
            });
        } catch (JdbiException e) {
            if (TransientSqlErrors.isTransient(e)) {
                throw new RetryableVulnAnalysisException("Failed to query matching criteria", e);
            }
            throw e;
        }
    }

    private void processCriteria(
            Map<Coordinate, List<MatchingCriteria>> criteriaListByCoordinate,
            Map<Coordinate, Set<CandidateComponent>> candidatesByCoordinate,
            Map<Long, Set<Long>> findingsByVuln,
            Map<Long, VulnMetadata> vulnMetadata) {
        for (final var entry : criteriaListByCoordinate.entrySet()) {
            final Coordinate coordinate = entry.getKey();
            final List<MatchingCriteria> criteriaList = entry.getValue();

            final Set<CandidateComponent> criteriaCandidates = candidatesByCoordinate.get(coordinate);
            if (criteriaCandidates == null || criteriaCandidates.isEmpty()) {
                LOGGER.warn("No candidates found for {}", coordinate);
                continue;
            }

            for (final MatchingCriteria criteria : criteriaList) {
                for (final var candidate : criteriaCandidates) {
                    final var affectedComponentIds = findingsByVuln.get(criteria.vulnDbId());
                    if (affectedComponentIds != null && affectedComponentIds.contains(candidate.id())) {
                        // Already matched, no need to check another criteria.
                        continue;
                    }

                    final boolean affected = switch (coordinate) {
                        case CpeCoordinate _ -> isAffectedByCpe(candidate, criteria);
                        case PurlCoordinate _ -> isAffectedByPurl(candidate, criteria);
                    };
                    if (affected) {
                        findingsByVuln
                                .computeIfAbsent(criteria.vulnDbId(), k -> new HashSet<>())
                                .add(candidate.id());
                        vulnMetadata.putIfAbsent(
                                criteria.vulnDbId(),
                                new VulnMetadata(criteria.vulnId(), criteria.vulnSource()));
                    }
                }
            }
        }
    }

    private boolean isAffectedByCpe(CandidateComponent component, MatchingCriteria criteria) {
        final Cpe targetCpe = component.parsedCpe();
        if (targetCpe == null || criteria.cpe23() == null) {
            return false;
        }
        if (!matchesCpe(targetCpe, criteria)) {
            return false;
        }

        final String targetVersion = targetCpe.getVersion();

        // Special cases for CPE matching of ANY (*) and NA (-) versions.
        // These don't make sense to use for version range comparison and
        // can be dealt with upfront based on the matching documentation:
        // https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
        if ("*".equals(targetVersion)) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 1   | ANY            | ANY        | EQUAL    |
            // | 5   | NA             | ANY        | SUBSET   |
            // | 13  | i              | ANY        | SUBSET   |
            // | 15  | m + wild cards | ANY        | SUBSET   |
            return true;
        } else if ("-".equals(targetVersion)) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 2   | ANY            | NA         | SUPERSET |
            // | 6   | NA             | NA         | EQUAL    |
            // | 12  | i              | NA         | DISJOINT |
            // | 16  | m + wild cards | NA         | DISJOINT |
            return "*".equals(criteria.version()) || "-".equals(criteria.version());
        }

        // Modified from original by Steve Springett
        // Added null check: vs.version() != null as purl sources that use version ranges may not have version populated.
        if (!criteria.hasRange()
                && criteria.version() != null
                && Cpe.compareAttribute(criteria.version(), targetVersion) != Relation.DISJOINT) {
            return true;
        }

        // If the component also has a PURL, use that to derive the versioning scheme.
        final String versioningScheme = Optional
                .ofNullable(component.parsedPurl())
                .flatMap(KnownVersioningSchemes::fromPurl)
                .orElse(SCHEME_GENERIC);

        return compareWithVers(criteria, targetVersion, versioningScheme);
    }

    private boolean isAffectedByPurl(CandidateComponent component, MatchingCriteria criteria) {
        final PackageURL componentPurl = component.parsedPurl();
        if (componentPurl == null || componentPurl.getVersion() == null) {
            return false;
        }
        if (!matchesPurl(componentPurl, criteria)) {
            return false;
        }
        if (!matchesDistro(componentPurl, criteria)) {
            return false;
        }

        final String versioningScheme =
                KnownVersioningSchemes.fromPurl(componentPurl)
                        .orElse(SCHEME_GENERIC);

        return compareWithVers(criteria, effectiveVersionOf(componentPurl), versioningScheme);
    }

    private static boolean matchesPurl(PackageURL componentPurl, MatchingCriteria criteria) {
        return Objects.equals(criteria.purlType(), componentPurl.getType())
                && Objects.equals(criteria.purlNamespace(), componentPurl.getNamespace())
                && Objects.equals(criteria.purlName(), componentPurl.getName());
    }

    private boolean compareWithVers(MatchingCriteria criteria, String targetVersion, String versioningScheme) {
        try {
            return buildVers(criteria, versioningScheme).contains(targetVersion);
        } catch (VersException | InvalidVersionException e) {
            // It's always possible that versatile has a bug, or that components / vulnerabilities
            // do not strictly follow versioning schemes. Fall back to the generic scheme to
            // prevent false negatives.
            if (!SCHEME_GENERIC.equals(versioningScheme)) {
                LOGGER.debug(
                        "Failed to compare {} against {} with scheme {}: {}; retrying with scheme {}",
                        targetVersion, criteria, versioningScheme, e.getMessage(), SCHEME_GENERIC);
                try {
                    return buildVers(criteria, SCHEME_GENERIC).contains(targetVersion);
                } catch (VersException | InvalidVersionException e2) {
                    LOGGER.warn(
                            "Failed to compare {} against {} with fallback: {}",
                            targetVersion, criteria, e2.getMessage());
                }
            } else {
                LOGGER.warn(
                        "Failed to compare {} against {}: {}",
                        targetVersion, criteria, e.getMessage());
            }

            return false;
        }
    }

    private static Vers buildVers(MatchingCriteria criteria, String versioningScheme) {
        final var versBuilder = Vers.builder(versioningScheme);

        if (criteria.versionStartIncluding() != null && !criteria.versionStartIncluding().isEmpty()) {
            versBuilder.withConstraint(Comparator.GREATER_THAN_OR_EQUAL, criteria.versionStartIncluding());
        }
        if (criteria.versionStartExcluding() != null && !criteria.versionStartExcluding().isEmpty()) {
            versBuilder.withConstraint(Comparator.GREATER_THAN, criteria.versionStartExcluding());
        }
        if (criteria.versionEndExcluding() != null && !criteria.versionEndExcluding().isEmpty()) {
            versBuilder.withConstraint(Comparator.LESS_THAN, criteria.versionEndExcluding());
        }
        if (criteria.versionEndIncluding() != null && !criteria.versionEndIncluding().isEmpty()) {
            versBuilder.withConstraint(Comparator.LESS_THAN_OR_EQUAL, criteria.versionEndIncluding());
        }

        if (criteria.version() == null && !versBuilder.hasConstraints()) {
            versBuilder.withConstraint(Comparator.WILDCARD, null);
        } else if (criteria.version() != null
                && !"*".equals(criteria.version())
                && !"-".equals(criteria.version())) {
            versBuilder.withConstraint(Comparator.EQUAL, criteria.version());
        }

        return versBuilder.build();
    }

    private static boolean matchesCpe(Cpe targetCpe, MatchingCriteria criteria) {
        final List<Relation> relations = List.of(
                Cpe.compareAttribute(criteria.cpePart(), targetCpe.getPart().getAbbreviation().toLowerCase()),
                Cpe.compareAttribute(criteria.cpeVendor(), targetCpe.getVendor().toLowerCase()),
                Cpe.compareAttribute(criteria.cpeProduct(), targetCpe.getProduct().toLowerCase()),
                Cpe.compareAttribute(criteria.version(), targetCpe.getVersion()),
                Cpe.compareAttribute(criteria.cpeUpdate(), targetCpe.getUpdate()),
                Cpe.compareAttribute(criteria.cpeEdition(), targetCpe.getEdition()),
                Cpe.compareAttribute(criteria.cpeLanguage(), targetCpe.getLanguage()),
                Cpe.compareAttribute(criteria.cpeSwEdition(), targetCpe.getSwEdition()),
                Cpe.compareAttribute(criteria.cpeTargetSw(), targetCpe.getTargetSw()),
                Cpe.compareAttribute(criteria.cpeTargetHw(), targetCpe.getTargetHw()),
                Cpe.compareAttribute(criteria.cpeOther(), targetCpe.getOther()));
        if (relations.contains(Relation.DISJOINT)) {
            return false;
        }

        boolean isMatch = true;

        // Mixed SUBSET / SUPERSET relations in the vendor and product attribute are prone
        // to false positives: https://github.com/DependencyTrack/dependency-track/issues/3178
        final Relation vendorRelation = relations.get(1);
        final Relation productRelation = relations.get(2);
        isMatch &= !(vendorRelation == Relation.SUBSET && productRelation == Relation.SUPERSET);
        isMatch &= !(vendorRelation == Relation.SUPERSET && productRelation == Relation.SUBSET);

        if (!isMatch && LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "{}: Dropped match with {} due to ambiguous vendor/product relation",
                    targetCpe.toCpe23FS(),
                    criteria.cpe23());
        }

        return isMatch;
    }

    private static void collectScannableComponents(List<Component> components, List<CandidateComponent> candidates) {
        for (final Component component : components) {
            if (!component.hasCpe() && !component.hasPurl()) {
                continue;
            }

            final long componentId;
            try {
                componentId = Long.parseLong(component.getBomRef());
            } catch (NumberFormatException e) {
                continue;
            }

            final Cpe parsedCpe = tryParseCpe(component);
            final PackageURL parsedPurl = tryParsePurl(component.getPurl());

            if (parsedCpe == null && parsedPurl == null) {
                continue;
            }

            candidates.add(new CandidateComponent(componentId, parsedCpe, parsedPurl));

            if (component.getComponentsCount() > 0) {
                collectScannableComponents(component.getComponentsList(), candidates);
            }
        }
    }

    private static @Nullable Cpe tryParseCpe(Component component) {
        if (!component.hasCpe()) {
            return null;
        }

        final Cpe parsed;
        try {
            parsed = CpeParser.parse(component.getCpe());
        } catch (CpeParsingException e) {
            LOGGER.warn("Failed to parse CPE '{}'", component.getCpe(), e);
            return null;
        }

        // Skip overly generic component CPEs to matching excessive quantities of vulns.
        // A non-concrete product (* / -) would expand to "every product from $vendor"
        // or "ALL products". Wildcard vendor with a concrete product is allowed,
        // since NVD vendor strings are inconsistent, and users may legitimately
        // use components like "cpe:2.3:a:*:openssl:..."
        final String product = parsed.getProduct();
        if ("*".equals(product) || "-".equals(product)) {
            LOGGER.debug("Ignoring CPE '{}': product is not concrete", component.getCpe());
            return null;
        }

        return parsed;
    }

    private static @Nullable PackageURL tryParsePurl(@Nullable String purl) {
        if (purl == null || purl.isEmpty()) {
            return null;
        }

        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to parse PURL '{}'", purl, e);
            return null;
        }
    }

    private static boolean matchesDistro(PackageURL componentPurl, MatchingCriteria criteria) {
        final String componentDistroQualifier = distroQualifierOf(componentPurl);
        final String vsDistroQualifier = distroQualifierOf(criteria.purl());

        // When both the component and the vulnerable software record have a distro
        // qualifier, they must match *before* we perform the actual version comparison.
        if (componentDistroQualifier != null && vsDistroQualifier != null) {
            // Simplest case: the qualifiers just match without special interpretation.
            if (!componentDistroQualifier.equals(vsDistroQualifier)) {
                // Could still match, but depends on distro semantics.
                // e.g. "debian-13" should match "trixie".
                final OsDistribution componentDistro = OsDistribution.of(componentPurl);
                final OsDistribution vsDistro = OsDistribution.of(criteria.purl());

                if (componentDistro != null && vsDistro != null) {
                    if (!componentDistro.matches(vsDistro)) {
                        // Actual mismatch, e.g. "debian-13" != "sid".
                        return false;
                    }
                } else if (componentDistro != null || vsDistro != null) {
                    // One side was parsed, the other wasn't. The raw qualifier
                    // strings already differ, so this is a mismatch.
                    return false;
                } else {
                    // Neither side could be parsed. The raw qualifier strings
                    // already differ, so treat as mismatch to avoid false positives.
                    LOGGER.debug("Neither distro qualifier could be parsed for comparison: {} vs {}",
                            componentDistroQualifier, vsDistroQualifier);
                    return false;
                }
            }
        }

        return true;
    }

    private static @Nullable String distroQualifierOf(@Nullable PackageURL purl) {
        if (purl == null) {
            return null;
        }

        final Map<String, String> qualifiers = purl.getQualifiers();
        return qualifiers != null ? qualifiers.get("distro") : null;
    }

    /**
     * Returns the PURL's version with any type-specific transformations applied to make it
     * suitable for ecosystem-aware comparison. Returns the raw version when no transformation
     * applies, or {@code null} if no version is set.
     * <p>
     * Applied transformations:
     * <ul>
     *   <li>{@code deb}/{@code rpm}: fold the {@code epoch} qualifier into the version as
     *       {@code <epoch>:<version>} when not already encoded inline.</li>
     * </ul>
     */
    private static String effectiveVersionOf(PackageURL purl) {
        requireNonNull(purl, "purl must not be null");
        requireNonNull(purl.getVersion(), "purl version must not be null");

        final String version = purl.getVersion();
        final String type = purl.getType();
        if (!PackageURL.StandardTypes.DEBIAN.equals(type)
                && !PackageURL.StandardTypes.RPM.equals(type)) {
            return version;
        }

        if (EPOCH_PREFIX_PATTERN.matcher(version).find()) {
            return version;
        }

        if (purl.getQualifiers() == null) {
            return version;
        }

        final String epoch = purl.getQualifiers().get("epoch");
        if (epoch == null || epoch.isBlank()) {
            return version;
        }

        return epoch + ":" + version;
    }

    private record VulnMetadata(String vulnId, String source) {
    }

}