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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.github.packageurl.PackageURL;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/// @since 5.2.0
@NullMarked
public interface DependencyGraphDao extends SqlObject {

    /// Retrieve the dependency graph of a [Project], expanded to every occurrence of the given components.
    ///
    /// @param projectUuid    UUID of the [Project] to retrieve the dependency graph of.
    /// @param componentUuids UUIDs of the components to expand the graph to.
    /// @return The expanded dependency graph, keyed by component UUID.
    default Map<UUID, GraphComponent> getDependencyGraph(UUID projectUuid, Collection<UUID> componentUuids) {
        final ProjectRow project = getProject(projectUuid);
        if (project == null
                || project.directDependencies() == null
                || project.directDependencies().isEmpty()) {
            return Map.of();
        }

        final Set<UUID> dependentUuids = getDependentUuids(project.id(), componentUuids);

        final var uuidsToFetch = new HashSet<>(componentUuids);
        uuidsToFetch.addAll(project.directDependencyUuids());
        uuidsToFetch.addAll(dependentUuids);

        // Retrieve the components on the path to the searched components,
        // the project's direct dependencies, and two levels of dependencies below those.
        //
        // NB: This behavior is coupled to how the frontend renders graphs.
        // Changing this will break the frontend, so make sure you test both if you do.
        final int dependencyLevels = 2;
        final var componentRowByUuid = new HashMap<UUID, ComponentRow>();
        final var dependencyUuidsByComponentUuid = new HashMap<UUID, Set<UUID>>();
        for (int level = 0; level <= dependencyLevels && !uuidsToFetch.isEmpty(); level++) {
            final var dependencyUuids = new HashSet<UUID>();
            for (final ComponentRow componentRow : getComponents(project.id(), uuidsToFetch)) {
                final UUID uuid = componentRow.uuid();
                componentRowByUuid.put(uuid, componentRow);

                if (level == dependencyLevels) {
                    continue;
                }

                final Set<UUID> directDependencyUuids = componentRow.directDependencyUuids();
                if (!directDependencyUuids.isEmpty()) {
                    dependencyUuidsByComponentUuid.put(uuid, directDependencyUuids);
                    dependencyUuids.addAll(directDependencyUuids);
                }
            }

            dependencyUuids.removeAll(componentRowByUuid.keySet());
            uuidsToFetch.clear();
            uuidsToFetch.addAll(dependencyUuids);
        }

        final var graphComponentByUuid = new HashMap<UUID, GraphComponent>(componentRowByUuid.size());
        for (final Map.Entry<UUID, ComponentRow> entry : componentRowByUuid.entrySet()) {
            final ComponentRow row = entry.getValue();
            graphComponentByUuid.put(
                    entry.getKey(),
                    new GraphComponent(
                            row.uuid(),
                            row.name(),
                            row.version(),
                            row.purl(),
                            row.purlCoordinates(),
                            dependencyUuidsByComponentUuid.get(entry.getKey()),
                            dependentUuids.contains(entry.getKey())));
        }

        return graphComponentByUuid;
    }

    @SqlQuery("""
        SELECT "ID"
             , "DIRECT_DEPENDENCIES"
          FROM "PROJECT"
         WHERE "UUID" = :projectUuid
        """)
    @RegisterConstructorMapper(ProjectRow.class)
    @Nullable
    ProjectRow getProject(@Bind UUID projectUuid);

    @SqlQuery("""
        WITH RECURSIVE cte_dependent ("UUID") AS (
          SELECT c."UUID"
            FROM "COMPONENT" AS c
           CROSS JOIN UNNEST(:componentUuids) AS dependency ("UUID")
           WHERE c."PROJECT_ID" = :projectId
             AND c."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', dependency."UUID"))
          UNION
          SELECT c."UUID"
            FROM "COMPONENT" AS c
           INNER JOIN cte_dependent AS dependency
              ON c."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', dependency."UUID"))
           WHERE c."PROJECT_ID" = :projectId
        )
        SELECT "UUID"
          FROM cte_dependent
        """)
    Set<UUID> getDependentUuids(@Bind long projectId, @Bind Collection<UUID> componentUuids);

    @SqlQuery("""
        SELECT "UUID"
             , "NAME"
             , "VERSION"
             , "PURL"
             , "PURLCOORDINATES"
             , "DIRECT_DEPENDENCIES"
          FROM "COMPONENT"
         WHERE "PROJECT_ID" = :projectId
           AND "UUID" = ANY(:componentUuids)
        """)
    @RegisterConstructorMapper(ComponentRow.class)
    List<ComponentRow> getComponents(@Bind long projectId, @Bind Collection<UUID> componentUuids);

    @JsonIgnoreProperties(ignoreUnknown = true)
    record DirectDependency(UUID uuid) {}

    record ProjectRow(long id, @Json @Nullable List<DirectDependency> directDependencies) {

        Set<UUID> directDependencyUuids() {
            if (directDependencies == null) {
                return Set.of();
            }

            return directDependencies.stream().map(DirectDependency::uuid).collect(Collectors.toSet());
        }
    }

    record ComponentRow(
            UUID uuid,
            String name,
            @Nullable String version,
            @Nullable PackageURL purl,
            @Nullable PackageURL purlCoordinates,
            @Json @Nullable List<DirectDependency> directDependencies) {

        Set<UUID> directDependencyUuids() {
            if (directDependencies == null) {
                return Set.of();
            }

            return directDependencies.stream().map(DirectDependency::uuid).collect(Collectors.toSet());
        }
    }

    record GraphComponent(
            UUID uuid,
            String name,
            @Nullable String version,
            @Nullable PackageURL purl,
            @Nullable PackageURL purlCoordinates,
            @Nullable Set<UUID> directDependencyUuids,
            boolean onSearchPath) {}
}
