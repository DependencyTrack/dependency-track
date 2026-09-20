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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.model.VulnerableSoftware;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.SequencedMap;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toUnmodifiableSet;

/// @since 5.2.0
public final class VulnerableSoftwareDao {

    private final Handle jdbiHandle;

    public VulnerableSoftwareDao(Handle jdbiHandle) {
        this.jdbiHandle = requireNonNull(jdbiHandle, "jdbiHandle must not be null");
    }

    public void syncAll(
            Vulnerability.Source source,
            Map<VulnerabilityKey, Long> vulnIdByKey,
            Map<VulnerabilityKey, List<VulnerableSoftware>> vsListByVulnKey) {
        requireNonNull(source, "source must not be null");
        if (vulnIdByKey.isEmpty()) {
            return;
        }

        final Map<Long, List<AssociatedVulnerableSoftware>> associatedVsByVulnDbId =
                getAssociatedVulnerableSoftware(vulnIdByKey.values());
        final Map<Long, Map<Long, Set<String>>> attributionSourcesByVulnDbId =
                getAttributionSources(vulnIdByKey.values());

        final var changeSets = new ArrayList<ChangeSet>(vulnIdByKey.size());
        final var unresolvedVsByKey = new LinkedHashMap<VulnerableSoftwareKey, VulnerableSoftware>();

        for (final Map.Entry<VulnerabilityKey, Long> entry : vulnIdByKey.entrySet()) {
            final long vulnDbId = entry.getValue();
            final ChangeSet changeSet = reconcile(
                    source,
                    vulnDbId,
                    vsListByVulnKey.getOrDefault(entry.getKey(), List.of()),
                    associatedVsByVulnDbId.getOrDefault(vulnDbId, List.of()),
                    attributionSourcesByVulnDbId.getOrDefault(vulnDbId, Map.of()));
            changeSets.add(changeSet);

            for (final VulnerableSoftware vs : changeSet.unresolvedVsList()) {
                unresolvedVsByKey.putIfAbsent(VulnerableSoftwareKey.of(vs), vs);
            }
        }

        final Map<VulnerableSoftwareKey, Long> vsDbIdByKey = resolveVulnerableSoftwareIds(unresolvedVsByKey);

        // NB: Neither the junction table nor the attribution table has a unique constraint,
        // hence using sets here is crucial.
        final var attributionsToCreate = new LinkedHashSet<VulnerableSoftwareAssociation>();
        final var attributionsToRefresh = new LinkedHashSet<VulnerableSoftwareAssociation>();
        final var attributionsToDelete = new LinkedHashSet<VulnerableSoftwareAssociation>();
        final var associationsToCreate = new LinkedHashSet<VulnerableSoftwareAssociation>();
        final var associationsToDelete = new LinkedHashSet<VulnerableSoftwareAssociation>();

        for (final ChangeSet changeSet : changeSets) {
            final long vulnDbId = changeSet.vulnDbId();
            final Map<Long, Set<String>> attributionSourcesByVsId =
                    attributionSourcesByVulnDbId.getOrDefault(vulnDbId, Map.of());

            for (final long vsDbId : changeSet.attributionsToCreate()) {
                attributionsToCreate.add(new VulnerableSoftwareAssociation(vulnDbId, vsDbId));
            }
            for (final long vsDbId : changeSet.attributionsToDelete()) {
                attributionsToDelete.add(new VulnerableSoftwareAssociation(vulnDbId, vsDbId));
            }
            for (final long vsDbId : changeSet.associationsToDelete()) {
                associationsToDelete.add(new VulnerableSoftwareAssociation(vulnDbId, vsDbId));
            }

            for (final VulnerableSoftware vs : changeSet.unresolvedVsList()) {
                final Long vsDbId = vsDbIdByKey.get(VulnerableSoftwareKey.of(vs));
                if (vsDbId == null) {
                    throw new IllegalStateException("No ID was resolved for vulnerable software " + vs);
                }

                final var association = new VulnerableSoftwareAssociation(vulnDbId, vsDbId);
                if (attributionSourcesByVsId.getOrDefault(vsDbId, Set.of()).contains(source.name())) {
                    // The attribution outlived the record's association with the vulnerability.
                    // Re-use it rather than replacing it, so its first-seen date survives.
                    attributionsToRefresh.add(association);
                } else {
                    attributionsToCreate.add(association);
                }

                if (!changeSet.associatedVsDbIds().contains(vsDbId)) {
                    associationsToCreate.add(association);
                }
            }
        }

        // A record can end up on both sides: dropped because it no longer matches by identity, yet
        // found again by the lookup, which compares fewer columns. The source still reports it,
        // so keep it rather than churning the rows.
        final var stillReported = new HashSet<>(attributionsToCreate);
        stillReported.addAll(attributionsToRefresh);
        attributionsToDelete.removeAll(stillReported);
        associationsToDelete.removeAll(stillReported);

        // Attributions of records that are no longer reported must go before new ones are added,
        // so that a record moving between sources within the same batch ends up attributed correctly.
        deleteAttributions(source, attributionsToDelete);
        refreshAttributions(source, attributionsToRefresh);
        createAttributions(source, attributionsToCreate);
        deleteAssociations(associationsToDelete);
        createAssociations(associationsToCreate);
    }

    private record ChangeSet(
            long vulnDbId,
            List<VulnerableSoftware> unresolvedVsList,
            Set<Long> associatedVsDbIds,
            List<Long> attributionsToCreate,
            List<Long> attributionsToDelete,
            List<Long> associationsToDelete) {}

    private record VulnerableSoftwareAssociation(long vulnDbId, long vsDbId) {}

    private record AssociatedVulnerableSoftware(long vsDbId, VulnerableSoftware vulnerableSoftware) {}

    private static ChangeSet reconcile(
            Vulnerability.Source source,
            long vulnDbId,
            List<VulnerableSoftware> reportedVsList,
            List<AssociatedVulnerableSoftware> associatedVsList,
            Map<Long, Set<String>> attributionSourcesByVsId) {
        final var unmatchedReportedVs = new ArrayList<>(reportedVsList);
        final var associatedVsDbIds = new HashSet<Long>(associatedVsList.size());
        final var attributionsToCreate = new ArrayList<Long>();
        final var attributionsToDelete = new ArrayList<Long>();
        final var associationsToDelete = new ArrayList<Long>();

        for (final AssociatedVulnerableSoftware associated : associatedVsList) {
            final Set<String> attributionSources = attributionSourcesByVsId.getOrDefault(associated.vsDbId(), Set.of());

            if (!associatedVsDbIds.add(associated.vsDbId())) {
                // NB: the junction table has no unique constraint, ignore repeated rows.
                continue;
            }

            if (unmatchedReportedVs.removeIf(associated.vulnerableSoftware()::equalsIgnoringDatastoreIdentity)) {
                if (!attributionSources.contains(source.name())) {
                    attributionsToCreate.add(associated.vsDbId());
                }
                continue;
            }

            // Dependency-Track versions prior to 4.7.0 did not record attributions.
            // Drop records without any. If another source still reports one,
            // it gets recorded and attributed the next time that source is mirrored.
            if (attributionSources.isEmpty() || attributionSources.contains(source.name())) {
                attributionsToDelete.add(associated.vsDbId());
                associationsToDelete.add(associated.vsDbId());
            }
        }

        return new ChangeSet(
                vulnDbId,
                unmatchedReportedVs,
                associatedVsDbIds,
                attributionsToCreate,
                attributionsToDelete,
                associationsToDelete);
    }

    private Map<Long, List<AssociatedVulnerableSoftware>> getAssociatedVulnerableSoftware(Collection<Long> vulnDbIds) {
        if (vulnDbIds.isEmpty()) {
            return Map.of();
        }

        return jdbiHandle
                .createQuery(/* language=SQL */ """
                    SELECT vsv."VULNERABILITY_ID"
                         , vs."ID"
                         , vs."PURL_TYPE"
                         , vs."PURL_NAMESPACE"
                         , vs."PURL_NAME"
                         , vs."PURL_QUALIFIERS"
                         , vs."PURL_SUBPATH"
                         , vs."CPE22"
                         , vs."CPE23"
                         , vs."PART"
                         , vs."VENDOR"
                         , vs."PRODUCT"
                         , vs."VERSION"
                         , vs."UPDATE"
                         , vs."EDITION"
                         , vs."LANGUAGE"
                         , vs."SWEDITION"
                         , vs."TARGETSW"
                         , vs."TARGETHW"
                         , vs."OTHER"
                         , vs."VERSIONENDEXCLUDING"
                         , vs."VERSIONENDINCLUDING"
                         , vs."VERSIONSTARTEXCLUDING"
                         , vs."VERSIONSTARTINCLUDING"
                         , vs."VULNERABLE"
                      FROM "VULNERABLESOFTWARE_VULNERABILITIES" AS vsv
                     INNER JOIN "VULNERABLESOFTWARE" AS vs
                        ON vs."ID" = vsv."VULNERABLESOFTWARE_ID"
                     WHERE vsv."VULNERABILITY_ID" = ANY(:vulnDbIds)
                    """)
                .bind("vulnDbIds", vulnDbIds.toArray(Long[]::new))
                .registerRowMapper(BeanMapper.factory(VulnerableSoftware.class))
                .reduceRows(new HashMap<Long, List<AssociatedVulnerableSoftware>>(), (associatedVsByVulnDbId, row) -> {
                    associatedVsByVulnDbId
                            .computeIfAbsent(row.getColumn("VULNERABILITY_ID", Long.class), _ -> new ArrayList<>())
                            .add(new AssociatedVulnerableSoftware(
                                    row.getColumn("ID", Long.class), row.getRow(VulnerableSoftware.class)));
                    return associatedVsByVulnDbId;
                });
    }

    private Map<Long, Map<Long, Set<String>>> getAttributionSources(Collection<Long> vulnDbIds) {
        if (vulnDbIds.isEmpty()) {
            return Map.of();
        }

        return jdbiHandle
                .createQuery(/* language=SQL */ """
                    SELECT "VULNERABILITY"
                         , "VULNERABLE_SOFTWARE"
                         , "SOURCE"
                      FROM "AFFECTEDVERSIONATTRIBUTION"
                     WHERE "VULNERABILITY" = ANY(:vulnDbIds)
                    """)
                .bind("vulnDbIds", vulnDbIds.toArray(Long[]::new))
                .map((rs, _) -> new Attribution(
                        rs.getLong("VULNERABILITY"), rs.getLong("VULNERABLE_SOFTWARE"), rs.getString("SOURCE")))
                .collect(groupingBy(
                        Attribution::vulnDbId,
                        groupingBy(Attribution::vsDbId, mapping(Attribution::source, toUnmodifiableSet()))));
    }

    private record Attribution(long vulnDbId, long vsDbId, String source) {}

    private Map<VulnerableSoftwareKey, Long> resolveVulnerableSoftwareIds(
            SequencedMap<VulnerableSoftwareKey, VulnerableSoftware> vsByKey) {
        if (vsByKey.isEmpty()) {
            return Map.of();
        }

        final var vsDbIdByKey = new HashMap<VulnerableSoftwareKey, Long>(vsByKey.size());
        vsDbIdByKey.putAll(findByCpe(vsByKey.keySet()));
        vsDbIdByKey.putAll(findByPurl(vsByKey.keySet()));

        final var missingVsByKey = new LinkedHashMap<VulnerableSoftwareKey, VulnerableSoftware>();
        for (final Map.Entry<VulnerableSoftwareKey, VulnerableSoftware> entry : vsByKey.entrySet()) {
            if (!vsDbIdByKey.containsKey(entry.getKey())) {
                missingVsByKey.put(entry.getKey(), entry.getValue());
            }
        }

        vsDbIdByKey.putAll(insertVulnerableSoftware(missingVsByKey));
        return vsDbIdByKey;
    }

    private Map<VulnerableSoftwareKey, Long> findByCpe(Collection<VulnerableSoftwareKey> keys) {
        final List<VulnerableSoftwareKey> cpeKeys =
                keys.stream().filter(key -> key.cpe23() != null).toList();
        if (cpeKeys.isEmpty()) {
            return Map.of();
        }

        final int size = cpeKeys.size();
        final var cpes = new String[size];
        final var versionEndExcluding = new String[size];
        final var versionEndIncluding = new String[size];
        final var versionStartExcluding = new String[size];
        final var versionStartIncluding = new String[size];

        int i = 0;
        for (final VulnerableSoftwareKey key : cpeKeys) {
            cpes[i] = key.cpe23();
            versionEndExcluding[i] = key.versionEndExcluding();
            versionEndIncluding[i] = key.versionEndIncluding();
            versionStartExcluding[i] = key.versionStartExcluding();
            versionStartIncluding[i] = key.versionStartIncluding();
            i++;
        }

        // NB: Only "CPE23" is compared with a plain equality, so that VULNERABLESOFTWARE_CPE23_VERSION_RANGE_IDX
        // can drive the join. The version range columns are nullable and must be compared NULL-safely,
        // which btree indexes can't do.
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                    SELECT MIN(vs."ID") AS "ID"
                         , t.ordinality AS "ORDINALITY"
                      FROM UNNEST(
                        :cpes
                      , :versionEndExcluding
                      , :versionEndIncluding
                      , :versionStartExcluding
                      , :versionStartIncluding
                      ) WITH ORDINALITY AS t(
                        cpe23
                      , version_end_excluding
                      , version_end_including
                      , version_start_excluding
                      , version_start_including
                      , ordinality
                      )
                     INNER JOIN "VULNERABLESOFTWARE" AS vs
                        ON vs."CPE23" = t.cpe23
                       AND vs."VERSIONENDEXCLUDING" IS NOT DISTINCT FROM t.version_end_excluding
                       AND vs."VERSIONENDINCLUDING" IS NOT DISTINCT FROM t.version_end_including
                       AND vs."VERSIONSTARTEXCLUDING" IS NOT DISTINCT FROM t.version_start_excluding
                       AND vs."VERSIONSTARTINCLUDING" IS NOT DISTINCT FROM t.version_start_including
                     GROUP BY t.ordinality
                    """)
                .bind("cpes", cpes)
                .bind("versionEndExcluding", versionEndExcluding)
                .bind("versionEndIncluding", versionEndIncluding)
                .bind("versionStartExcluding", versionStartExcluding)
                .bind("versionStartIncluding", versionStartIncluding)
                .map((rs, _) -> Map.entry(cpeKeys.get(rs.getInt("ORDINALITY") - 1), rs.getLong("ID")))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Map<VulnerableSoftwareKey, Long> findByPurl(Collection<VulnerableSoftwareKey> keys) {
        // NB: Do separate lookups depending on whether the PURL namespace is null.
        // The backing index is only usable when null values are provided as literals.
        final Map<VulnerableSoftwareKey, Long> vsDbIdByKey = new HashMap<>(findByPurl(
                keys.stream()
                        .filter(key -> key.purlType() != null && key.purlNamespace() != null)
                        .toList(),
                /* namespaceIsNull */ false));

        vsDbIdByKey.putAll(findByPurl(
                keys.stream()
                        .filter(key -> key.purlType() != null && key.purlNamespace() == null)
                        .toList(),
                /* namespaceIsNull */ true));

        return vsDbIdByKey;
    }

    private Map<VulnerableSoftwareKey, Long> findByPurl(List<VulnerableSoftwareKey> purlKeys, boolean namespaceIsNull) {
        if (purlKeys.isEmpty()) {
            return Map.of();
        }

        final int size = purlKeys.size();
        final var purlTypes = new String[size];
        final var purlNamespaces = new String[size];
        final var purlNames = new String[size];
        final var purlQualifiers = new String[size];
        final var purlSubpaths = new String[size];
        final var versions = new String[size];
        final var versionEndExcluding = new String[size];
        final var versionEndIncluding = new String[size];
        final var versionStartExcluding = new String[size];
        final var versionStartIncluding = new String[size];

        int i = 0;
        for (final VulnerableSoftwareKey key : purlKeys) {
            purlTypes[i] = key.purlType();
            purlNamespaces[i] = key.purlNamespace();
            purlNames[i] = key.purlName();
            purlQualifiers[i] = key.purlQualifiers();
            purlSubpaths[i] = key.purlSubpath();
            versions[i] = key.version();
            versionEndExcluding[i] = key.versionEndExcluding();
            versionEndIncluding[i] = key.versionEndIncluding();
            versionStartExcluding[i] = key.versionStartExcluding();
            versionStartIncluding[i] = key.versionStartIncluding();
            i++;
        }

        final Query query = jdbiHandle.createQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="namespaceIsNull" type="boolean" -->
            SELECT MIN(vs."ID") AS "ID"
                 , t.ordinality AS "ORDINALITY"
              FROM UNNEST(
                :purlTypes
              , :purlNamespaces
              , :purlNames
              , :purlQualifiers
              , :purlSubpaths
              , :versions
              , :versionEndExcluding
              , :versionEndIncluding
              , :versionStartExcluding
              , :versionStartIncluding
              ) WITH ORDINALITY AS t(
                purl_type
              , purl_namespace
              , purl_name
              , purl_qualifiers
              , purl_subpath
              , version
              , version_end_excluding
              , version_end_including
              , version_start_excluding
              , version_start_including
              , ordinality
              )
             INNER JOIN "VULNERABLESOFTWARE" AS vs
                ON vs."PURL_TYPE" = t.purl_type
               AND <#if namespaceIsNull>vs."PURL_NAMESPACE" IS NULL<#else>vs."PURL_NAMESPACE" = t.purl_namespace</#if>
               AND vs."PURL_NAME" = t.purl_name
               AND vs."PURL_QUALIFIERS" IS NOT DISTINCT FROM t.purl_qualifiers
               AND vs."PURL_SUBPATH" IS NOT DISTINCT FROM t.purl_subpath
               AND vs."VERSION" IS NOT DISTINCT FROM t.version
               AND vs."VERSIONENDEXCLUDING" IS NOT DISTINCT FROM t.version_end_excluding
               AND vs."VERSIONENDINCLUDING" IS NOT DISTINCT FROM t.version_end_including
               AND vs."VERSIONSTARTEXCLUDING" IS NOT DISTINCT FROM t.version_start_excluding
               AND vs."VERSIONSTARTINCLUDING" IS NOT DISTINCT FROM t.version_start_including
             GROUP BY t.ordinality
            """);

        return query.define("namespaceIsNull", namespaceIsNull)
                .bind("purlTypes", purlTypes)
                .bind("purlNamespaces", purlNamespaces)
                .bind("purlNames", purlNames)
                .bind("purlQualifiers", purlQualifiers)
                .bind("purlSubpaths", purlSubpaths)
                .bind("versions", versions)
                .bind("versionEndExcluding", versionEndExcluding)
                .bind("versionEndIncluding", versionEndIncluding)
                .bind("versionStartExcluding", versionStartExcluding)
                .bind("versionStartIncluding", versionStartIncluding)
                .map((rs, _) -> Map.entry(purlKeys.get(rs.getInt("ORDINALITY") - 1), rs.getLong("ID")))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Map<VulnerableSoftwareKey, Long> insertVulnerableSoftware(
            SequencedMap<VulnerableSoftwareKey, VulnerableSoftware> vsByKey) {
        if (vsByKey.isEmpty()) {
            return Map.of();
        }

        final int size = vsByKey.size();
        // UUIDs are generated up-front because RETURNING gives no way to tell
        // which input row an ID belongs to; the ORDER BY below reshuffles them.
        final var uuids = new UUID[size];
        final var keysByUuid = new HashMap<UUID, VulnerableSoftwareKey>(size);
        final var purls = new String[size];
        final var purlTypes = new String[size];
        final var purlNamespaces = new String[size];
        final var purlNames = new String[size];
        final var purlVersions = new String[size];
        final var purlQualifiers = new String[size];
        final var purlSubpaths = new String[size];
        final var cpe22s = new String[size];
        final var cpe23s = new String[size];
        final var parts = new String[size];
        final var vendors = new String[size];
        final var products = new String[size];
        final var versions = new String[size];
        final var updates = new String[size];
        final var editions = new String[size];
        final var languages = new String[size];
        final var swEditions = new String[size];
        final var targetSws = new String[size];
        final var targetHws = new String[size];
        final var others = new String[size];
        final var versionEndExcluding = new String[size];
        final var versionEndIncluding = new String[size];
        final var versionStartExcluding = new String[size];
        final var versionStartIncluding = new String[size];
        final var vulnerable = new Boolean[size];

        int i = 0;
        for (final Map.Entry<VulnerableSoftwareKey, VulnerableSoftware> entry : vsByKey.entrySet()) {
            final VulnerableSoftware vs = entry.getValue();
            uuids[i] = UUID.randomUUID();
            keysByUuid.put(uuids[i], entry.getKey());
            purls[i] = vs.getPurl();
            purlTypes[i] = vs.getPurlType();
            purlNamespaces[i] = vs.getPurlNamespace();
            purlNames[i] = vs.getPurlName();
            purlVersions[i] = vs.getPurlVersion();
            purlQualifiers[i] = vs.getPurlQualifiers();
            purlSubpaths[i] = vs.getPurlSubpath();
            cpe22s[i] = vs.getCpe22();
            cpe23s[i] = vs.getCpe23();
            parts[i] = vs.getPart();
            vendors[i] = vs.getVendor();
            products[i] = vs.getProduct();
            versions[i] = vs.getVersion();
            updates[i] = vs.getUpdate();
            editions[i] = vs.getEdition();
            languages[i] = vs.getLanguage();
            swEditions[i] = vs.getSwEdition();
            targetSws[i] = vs.getTargetSw();
            targetHws[i] = vs.getTargetHw();
            others[i] = vs.getOther();
            versionEndExcluding[i] = vs.getVersionEndExcluding();
            versionEndIncluding[i] = vs.getVersionEndIncluding();
            versionStartExcluding[i] = vs.getVersionStartExcluding();
            versionStartIncluding[i] = vs.getVersionStartIncluding();
            vulnerable[i] = vs.isVulnerable();
            i++;
        }

        final Query query = jdbiHandle.createQuery(/* language=SQL */ """
            INSERT INTO "VULNERABLESOFTWARE" (
              "UUID"
            , "PURL"
            , "PURL_TYPE"
            , "PURL_NAMESPACE"
            , "PURL_NAME"
            , "PURL_VERSION"
            , "PURL_QUALIFIERS"
            , "PURL_SUBPATH"
            , "CPE22"
            , "CPE23"
            , "PART"
            , "VENDOR"
            , "PRODUCT"
            , "VERSION"
            , "UPDATE"
            , "EDITION"
            , "LANGUAGE"
            , "SWEDITION"
            , "TARGETSW"
            , "TARGETHW"
            , "OTHER"
            , "VERSIONENDEXCLUDING"
            , "VERSIONENDINCLUDING"
            , "VERSIONSTARTEXCLUDING"
            , "VERSIONSTARTINCLUDING"
            , "VULNERABLE"
            )
            SELECT *
              FROM UNNEST(
                :uuids
              , :purls
              , :purlTypes
              , :purlNamespaces
              , :purlNames
              , :purlVersions
              , :purlQualifiers
              , :purlSubpaths
              , :cpe22s
              , :cpe23s
              , :parts
              , :vendors
              , :products
              , :versions
              , :updates
              , :editions
              , :languages
              , :swEditions
              , :targetSws
              , :targetHws
              , :others
              , :versionEndExcluding
              , :versionEndIncluding
              , :versionStartExcluding
              , :versionStartIncluding
              , :vulnerable
              ) AS t (
                uuid
              , purl
              , purl_type
              , purl_namespace
              , purl_name
              , purl_version
              , purl_qualifiers
              , purl_subpath
              , cpe22
              , cpe23
              , part
              , vendor
              , product
              , version
              , cpe_update
              , edition
              , language
              , sw_edition
              , target_sw
              , target_hw
              , other
              , version_end_excluding
              , version_end_including
              , version_start_excluding
              , version_start_including
              , vulnerable
              )
             -- NB: Rows are ordered here, and in the other statements below, to keep the
             -- order in which row locks are taken consistent across concurrent mirror runs.
             ORDER BY t.cpe23
                    , t.purl_type
                    , t.purl_namespace
                    , t.purl_name
                    , t.purl_qualifiers
                    , t.purl_subpath
                    , t.version
                    , t.version_end_excluding
                    , t.version_end_including
                    , t.version_start_excluding
                    , t.version_start_including
            RETURNING "ID", "UUID"
            """);

        return query.registerArrayType(Boolean.class, "bool")
                .bind("uuids", uuids)
                .bind("purls", purls)
                .bind("purlTypes", purlTypes)
                .bind("purlNamespaces", purlNamespaces)
                .bind("purlNames", purlNames)
                .bind("purlVersions", purlVersions)
                .bind("purlQualifiers", purlQualifiers)
                .bind("purlSubpaths", purlSubpaths)
                .bind("cpe22s", cpe22s)
                .bind("cpe23s", cpe23s)
                .bind("parts", parts)
                .bind("vendors", vendors)
                .bind("products", products)
                .bind("versions", versions)
                .bind("updates", updates)
                .bind("editions", editions)
                .bind("languages", languages)
                .bind("swEditions", swEditions)
                .bind("targetSws", targetSws)
                .bind("targetHws", targetHws)
                .bind("others", others)
                .bind("versionEndExcluding", versionEndExcluding)
                .bind("versionEndIncluding", versionEndIncluding)
                .bind("versionStartExcluding", versionStartExcluding)
                .bind("versionStartIncluding", versionStartIncluding)
                .bind("vulnerable", vulnerable)
                .map((rs, _) ->
                        Map.entry(requireNonNull(keysByUuid.get(rs.getObject("UUID", UUID.class))), rs.getLong("ID")))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private void createAttributions(
            Vulnerability.Source source, Collection<VulnerableSoftwareAssociation> associations) {
        if (associations.isEmpty()) {
            return;
        }

        final AssociationColumns columns = AssociationColumns.of(associations);
        jdbiHandle
                .createUpdate(/* language=SQL */ """
                    INSERT INTO "AFFECTEDVERSIONATTRIBUTION" (
                      "VULNERABILITY"
                    , "VULNERABLE_SOFTWARE"
                    , "SOURCE"
                    , "FIRST_SEEN"
                    )
                    SELECT t.vuln_id
                         , t.vs_id
                         , :source
                         , :firstSeen
                      FROM UNNEST(:vulnDbIds, :vsDbIds)
                        AS t(vuln_id, vs_id)
                     ORDER BY t.vuln_id
                            , t.vs_id
                    """)
                .bind("source", source.name())
                .bind("firstSeen", Timestamp.from(Instant.now()))
                .bind("vulnDbIds", columns.vulnDbIds())
                .bind("vsDbIds", columns.vsDbIds())
                .execute();
    }

    private void refreshAttributions(
            Vulnerability.Source source, Collection<VulnerableSoftwareAssociation> associations) {
        if (associations.isEmpty()) {
            return;
        }

        final AssociationColumns columns = AssociationColumns.of(associations);
        jdbiHandle
                .createUpdate(/* language=SQL */ """
                    UPDATE "AFFECTEDVERSIONATTRIBUTION"
                       SET "FIRST_SEEN" = :firstSeen
                      FROM (
                        SELECT vuln_id
                             , vs_id
                          FROM UNNEST(:vulnDbIds, :vsDbIds)
                            AS u(vuln_id, vs_id)
                         ORDER BY vuln_id
                                , vs_id
                      ) AS t
                     WHERE "AFFECTEDVERSIONATTRIBUTION"."SOURCE" = :source
                       AND "AFFECTEDVERSIONATTRIBUTION"."VULNERABILITY" = t.vuln_id
                       AND "AFFECTEDVERSIONATTRIBUTION"."VULNERABLE_SOFTWARE" = t.vs_id
                    """)
                .bind("source", source.name())
                .bind("firstSeen", Timestamp.from(Instant.now()))
                .bind("vulnDbIds", columns.vulnDbIds())
                .bind("vsDbIds", columns.vsDbIds())
                .execute();
    }

    private void deleteAttributions(
            Vulnerability.Source source, Collection<VulnerableSoftwareAssociation> associations) {
        if (associations.isEmpty()) {
            return;
        }

        final var columns = AssociationColumns.of(associations);
        jdbiHandle
                .createUpdate(/* language=SQL */ """
                    DELETE
                      FROM "AFFECTEDVERSIONATTRIBUTION"
                     WHERE "SOURCE" = :source
                       AND ("VULNERABILITY", "VULNERABLE_SOFTWARE") IN (
                         SELECT vuln_id
                              , vs_id
                           FROM UNNEST(:vulnDbIds, :vsDbIds)
                             AS t(vuln_id, vs_id)
                          ORDER BY vuln_id
                                 , vs_id
                       )
                    """)
                .bind("source", source.name())
                .bind("vulnDbIds", columns.vulnDbIds())
                .bind("vsDbIds", columns.vsDbIds())
                .execute();
    }

    private void createAssociations(Collection<VulnerableSoftwareAssociation> associations) {
        if (associations.isEmpty()) {
            return;
        }

        final var columns = AssociationColumns.of(associations);
        jdbiHandle
                .createUpdate(/* language=SQL */ """
                    INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" (
                      "VULNERABILITY_ID"
                    , "VULNERABLESOFTWARE_ID"
                    )
                    SELECT *
                      FROM UNNEST(:vulnDbIds, :vsDbIds)
                        AS t(vuln_id, vs_id)
                     ORDER BY t.vuln_id
                            , t.vs_id
                    """)
                .bind("vulnDbIds", columns.vulnDbIds())
                .bind("vsDbIds", columns.vsDbIds())
                .execute();
    }

    private void deleteAssociations(Collection<VulnerableSoftwareAssociation> associations) {
        if (associations.isEmpty()) {
            return;
        }

        final var columns = AssociationColumns.of(associations);
        jdbiHandle
                .createUpdate(/* language=SQL */ """
                    DELETE
                      FROM "VULNERABLESOFTWARE_VULNERABILITIES"
                     WHERE ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID") IN (
                       SELECT vuln_id
                            , vs_id
                         FROM UNNEST(:vulnDbIds, :vsDbIds) AS t(vuln_id, vs_id)
                        ORDER BY vuln_id
                               , vs_id
                     )
                    """)
                .bind("vulnDbIds", columns.vulnDbIds())
                .bind("vsDbIds", columns.vsDbIds())
                .execute();
    }

    private record AssociationColumns(Long[] vulnDbIds, Long[] vsDbIds) {

        private static AssociationColumns of(Collection<VulnerableSoftwareAssociation> associations) {
            final var vulnDbIds = new Long[associations.size()];
            final var vsDbIds = new Long[associations.size()];

            int i = 0;
            for (final VulnerableSoftwareAssociation association : associations) {
                vulnDbIds[i] = association.vulnDbId();
                vsDbIds[i] = association.vsDbId();
                i++;
            }

            return new AssociationColumns(vulnDbIds, vsDbIds);
        }
    }

    private record VulnerableSoftwareKey(
            @Nullable String cpe23,
            @Nullable String purlType,
            @Nullable String purlNamespace,
            @Nullable String purlName,
            @Nullable String purlQualifiers,
            @Nullable String purlSubpath,
            @Nullable String version,
            @Nullable String versionEndExcluding,
            @Nullable String versionEndIncluding,
            @Nullable String versionStartExcluding,
            @Nullable String versionStartIncluding) {

        private static VulnerableSoftwareKey of(VulnerableSoftware vs) {
            if (vs.getCpe23() != null) {
                return new VulnerableSoftwareKey(
                        vs.getCpe23(),
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        vs.getVersionEndExcluding(),
                        vs.getVersionEndIncluding(),
                        vs.getVersionStartExcluding(),
                        vs.getVersionStartIncluding());
            }

            if (vs.getPurl() != null) {
                return new VulnerableSoftwareKey(
                        null,
                        vs.getPurlType(),
                        vs.getPurlNamespace(),
                        vs.getPurlName(),
                        vs.getPurlQualifiers(),
                        vs.getPurlSubpath(),
                        vs.getVersion(),
                        vs.getVersionEndExcluding(),
                        vs.getVersionEndIncluding(),
                        vs.getVersionStartExcluding(),
                        vs.getVersionStartIncluding());
            }

            throw new IllegalStateException(
                    "VulnerableSoftware must define a CPE or PURL, but %s has neither".formatted(vs));
        }
    }
}
