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
package org.dependencytrack.persistence;

import alpine.model.IConfigProperty.PropertyType;
import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonValue;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.sqlmapping.ComponentProjection;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;
import org.dependencytrack.util.PurlUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.model.sqlmapping.ComponentProjection.mapToComponent;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

final class ComponentQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    ComponentQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ComponentQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public boolean hasComponents(Project project) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT EXISTS(SELECT 1 FROM "COMPONENT" WHERE "PROJECT_ID" = ?)
                """);
        query.setParameters(project.getId());
        return executeAndCloseResultUnique(query, Boolean.class);
    }

    /**
     * Returns a List of all Components for the specified Project.
     * This method if designed NOT to provide paginated results.
     *
     * @param project the Project to retrieve dependencies of
     * @return a List of Component objects
     */
    @SuppressWarnings("unchecked")
    public List<Component> getAllComponents(Project project) {
        final Query<Component> query = pm.newQuery(Component.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        query.setOrdering("name asc");
        return (List<Component>) query.execute(project);
    }

    /**
     * Returns a List of Dependency for the specified Project.
     *
     * @param project        the Project to retrieve dependencies of
     * @param includeMetrics Optionally includes third-party metadata about the component from external repositories
     * @param onlyOutdated   Optionally exclude recent components so only outdated components are shown
     * @param onlyDirect     Optionally exclude transitive dependencies so only direct dependencies are shown
     * @return a List of Dependency objects
     */
    public PaginatedResult getComponents(final Project project, final boolean includeMetrics, final boolean onlyOutdated, final boolean onlyDirect) {
        List<Component> componentsResult = new ArrayList<>();
        String queryString = """
                        SELECT "A0"."ID" AS "id",
                        "A0"."NAME" AS "name",
                        "A0"."AUTHORS" AS "authors",
                        "A0"."BLAKE2B_256" AS "blake2b_256",
                        "A0"."BLAKE2B_384" AS "blake2b_384",
                        "A0"."BLAKE2B_512" AS "blake2b_512",
                        "A0"."BLAKE3" AS "blake3",
                        "A0"."CLASSIFIER" AS "classifier",
                        "A0"."COPYRIGHT" AS "copyright",
                        "A0"."CPE" AS "cpe",
                        "A0"."PUBLISHER" AS "publisher",
                        "A0"."PURL" AS "purl",
                        "A0"."PURLCOORDINATES" AS "purlCoordinates",
                        "A0"."DESCRIPTION" AS "description",
                        "A0"."DIRECT_DEPENDENCIES" AS "directDependencies",
                        "A0"."EXTENSION" AS "extension",
                        "A0"."EXTERNAL_REFERENCES" AS "externalReferences",
                        "A0"."FILENAME" AS "filename",
                        "A0"."GROUP" AS "group",
                        "A0"."INTERNAL" AS "internal",
                        "A0"."LAST_RISKSCORE" AS "lastInheritedRiskScore",
                        "A0"."LICENSE" AS "componentLicenseName",
                        "A0"."LICENSE_EXPRESSION" AS "licenseExpression",
                        "A0"."LICENSE_URL" AS "licenseUrl",
                        "A0"."TEXT" AS "text",
                        "A0"."MD5" AS "md5",
                        "A0"."SHA1" AS "sha1",
                        "A0"."SHA_256" AS "sha256",
                        "A0"."SHA_384" AS "sha384",
                        "A0"."SHA_512" AS "sha512",
                        "A0"."SHA3_256" AS "sha3_256",
                        "A0"."SHA3_384" AS "sha3_384",
                        "A0"."SHA3_512" AS "sha3_512",
                        "A0"."SWIDTAGID" AS "swidTagId",
                        "A0"."UUID" AS "uuid",
                        "A0"."VERSION" AS "version",
                        "A0"."SCOPE" AS "scope",
                        "B0"."INACTIVE_SINCE" AS "projectInactiveSince",
                        "B0"."AUTHORS" AS "projectAuthors",
                        "B0"."CLASSIFIER" AS "projectClassifier",
                        "B0"."CPE" AS "projectCpe",
                        "B0"."DESCRIPTION" AS "projectDescription",
                        "B0"."DIRECT_DEPENDENCIES" AS "projectDirectDependencies",
                        "B0"."EXTERNAL_REFERENCES" AS "projectExternalReferences",
                        "B0"."GROUP" AS "projectGroup",
                        "B0"."ID" AS "projectId",
                        "B0"."LAST_BOM_IMPORTED" AS "lastBomImport",
                        "B0"."LAST_BOM_IMPORTED_FORMAT" AS "lastBomImportFormat",
                        "B0"."LAST_RISKSCORE" AS "projectLastInheritedRiskScore",
                        "B0"."NAME" AS "projectName",
                        "B0"."PUBLISHER" AS "projectPublisher",
                        "B0"."PURL" AS "projectPurl",
                        "B0"."SWIDTAGID" AS "projectSwidTagId",
                        "B0"."UUID" AS "projectUuid",
                        "B0"."VERSION" AS "projectVersion",
                        "D0"."ISCUSTOMLICENSE" AS "isCustomLicense",
                        "D0"."FSFLIBRE" AS "isFsfLibre",
                        "D0"."LICENSEID" AS "licenseId",
                        "D0"."ISOSIAPPROVED" AS "isOsiApproved",
                        "D0"."UUID" AS "licenseUuid",
                        "D0"."NAME" AS "licenseName",
                        (SELECT COUNT(*) FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = "A0"."ID") AS "occurrenceCount",
                        COUNT(*) OVER() AS "totalCount"
                FROM "COMPONENT" "A0"
                INNER JOIN "PROJECT" "B0" ON "A0"."PROJECT_ID" = "B0"."ID"
                LEFT OUTER JOIN "LICENSE" "D0" ON "A0"."LICENSE_ID" = "D0"."ID"
                WHERE "A0"."PROJECT_ID" = :projectId
                """;

        final var queryParams = new HashMap<String, Object>();
        queryParams.put("projectId", project.getId());
        if (filter != null) {
            queryString += """
                    AND (LOWER("A0"."NAME") LIKE ('%' || LOWER(:nameFilter) || '%')
                    OR LOWER("A0"."GROUP") LIKE ('%' || LOWER(:nameFilter) || '%'))
                    """;
            queryParams.put("nameFilter", filter);
        }

        if (onlyOutdated) {
            queryString += /* language=SQL */ """
                    AND EXISTS (
                      SELECT 1
                        FROM "PACKAGE_ARTIFACT_METADATA" "PAM"
                       INNER JOIN "PACKAGE_METADATA" "PM"
                          ON "PM"."PURL" = "PAM"."PACKAGE_PURL"
                       WHERE "PAM"."PURL" = "A0"."PURL"
                         AND "PM"."LATEST_VERSION" != "A0"."VERSION"
                    )
                    """;
        }
        if (onlyDirect) {
            queryString +=
                    """
                       AND "B0"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "A0"."UUID"))
                    """;
        }
        if (orderBy == null) {
            queryString +=
                    """
                        ORDER BY "name",
                        "version" DESC
                    """;
        } else {
            if (orderBy.equalsIgnoreCase("version")) {
                queryString +=
                        """
                            ORDER BY "version"
                        """;
            }
            if (orderBy.equalsIgnoreCase("name")) {
                queryString +=
                        """
                            ORDER BY "name"
                        """;
            }
            if (orderBy.equalsIgnoreCase("group")) {
                queryString +=
                        """
                            ORDER BY "group"
                        """;
            }
            if (orderBy.equalsIgnoreCase("lastInheritedRiskScore")) {
                queryString +=
                        """
                            ORDER BY "lastInheritedRiskScore"
                        """;
            }
            if (orderBy.equalsIgnoreCase("occurrenceCount")) {
                queryString += "ORDER BY \"occurrenceCount\"";
            }
            if (queryString.contains("ORDER BY")) {
                if (orderDirection == OrderDirection.ASCENDING) {
                    queryString += " ASC ";
                } else if (orderDirection == OrderDirection.DESCENDING) {
                    queryString += " DESC ";
                }
                queryString += """
                        , "id"
                        """;
            }
        }

        if (pagination != null && pagination.isPaginated()) {
            queryString +=
                    """
                        OFFSET %d
                        LIMIT %d;
                    """.formatted(pagination.getOffset(), pagination.getLimit());
        }

        Query<?> query = pm.newQuery(Query.SQL, queryString);
        query.setNamedParameters(queryParams);
        final var components = new ArrayList<Component>();
        long totalCount = 0;
        try {
            for (final var componentProjection : query.executeResultList(ComponentProjection.class)) {
                components.add(mapToComponent(componentProjection));
                totalCount = componentProjection.totalCount;
            }
        } finally {
            query.closeAll();
        }

        if (!components.isEmpty() && includeMetrics) {
            populateRepositoryMetadata(components);
            populateMetrics(components);
        }

        return (new PaginatedResult()).objects(components).total(totalCount);
    }

    /**
     * Returns Components by their hash.
     *
     * @param hash the hash of the component to retrieve
     * @return a list of components
     */
    public PaginatedResult getComponentByHash(String hash) {
        if (hash == null) {
            return null;
        }

        final String queryFilter = switch (hash.length()) {
            case 32 -> "(md5 == :hash)";
            case 40 -> "(sha1 == :hash)";
            case 64 -> "(sha256 == :hash || sha3_256 == :hash || blake2b_256 == :hash)";
            case 96 -> "(sha384 == :hash || sha3_384 == :hash || blake2b_384 == :hash)";
            case 128 -> "(sha512 == :hash || sha3_512 == :hash || blake2b_512 == :hash)";
            default -> "(blake3 == :hash)";
        };

        final Query<Component> query = pm.newQuery(Component.class);
        final Map<String, Object> params = Map.of("hash", hash);
        preprocessACLs(query, queryFilter, params);
        return execute(query, params);
    }

    /**
     * Returns components by their identity, optionally scoped to active projects, latest-version
     * projects, or both.
     * @param identity the ComponentIdentity to query against
     * @param project the {@link Project} the {@link Component}s belong to
     * @param includeMetrics whether to include component metrics
     * @param excludeInactiveProjects when {@code true}, return only components from active projects
     * @param onlyLatestProjectVersions when {@code true}, return only components from projects flagged as the latest version
     * @return a list of components
     */
    public PaginatedResult getComponents(
            ComponentIdentity identity,
            Project project,
            boolean includeMetrics,
            boolean excludeInactiveProjects,
            boolean onlyLatestProjectVersions) {
        if (identity == null) {
            return null;
        }

        final var queryFilterElements = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();

        if (project != null) {
            queryFilterElements.add(" project == :project ");
            queryParams.put("project", project);
        }
        if (excludeInactiveProjects) {
            queryFilterElements.add(" project.inactiveSince == null ");
        }
        if (onlyLatestProjectVersions) {
            queryFilterElements.add(" project.isLatest == true ");
        }

        final PaginatedResult result;
        if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) {
            if (identity.getGroup() != null) {
                queryFilterElements.add(" group.toLowerCase().matches(:group) ");
                queryParams.put("group", ".*" + identity.getGroup().toLowerCase() + ".*");
            }
            if (identity.getName() != null) {
                queryFilterElements.add(" name.toLowerCase().matches(:name) ");
                queryParams.put("name", ".*" + identity.getName().toLowerCase() + ".*");
            }
            if (identity.getVersion() != null) {
                queryFilterElements.add(" version.toLowerCase().matches(:version) ");
                queryParams.put("version", ".*" + identity.getVersion().toLowerCase() + ".*");
            }

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else if (identity.getPurl() != null) {
            // "contains" conditions with wildcards on both sides don't make sense here
            // given we already require a valid PURL to be provided. There will always
            // be a mandatory prefix such as "pkg:npm/foo".
            queryFilterElements.add("purl.toLowerCase().startsWith(:purl)");
            queryParams.put("purl", identity.getPurl().canonicalize().toLowerCase());

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else if (identity.getCpe() != null) {
            queryFilterElements.add("cpe.toLowerCase().matches(:cpe)");
            queryParams.put("cpe", ".*" + identity.getCpe().toLowerCase() + ".*");

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else if (identity.getSwidTagId() != null) {
            queryFilterElements.add("swidTagId.toLowerCase().matches(:swidTagId)");
            queryParams.put("swidTagId", ".*" + identity.getSwidTagId().toLowerCase() + ".*");

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else {
            result = new PaginatedResult();
        }

        if (!result.getObjects().isEmpty() && includeMetrics) {
            final List<Component> components = result.getList(Component.class);
            populateRepositoryMetadata(components);
            populateMetrics(components);
        }

        for (Component component : result.getList(Component.class)) {
            component.getProject(); // Force loading of project
            component.getProject().getGroup();
            component.getProject().getName();
            component.getProject().getVersion();
            component.getProject().getSwidTagId();
            component.getProject().getCpe();
            component.getProject().getUuid();
        }
        return result;
    }

    private PaginatedResult loadComponents(String queryFilter, Map<String, Object> params) {
        var query = pm.newQuery(Component.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        preprocessACLs(query, queryFilter, params);
        return execute(query, params);
    }

    /**
     * Creates a new Component.
     *
     * @param component   the Component to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new Component
     */
    public Component createComponent(Component component, boolean commitIndex) {
        final Component result = persist(component);
        return result;
    }

    /**
     * Updated an existing Component.
     *
     * @param transientComponent the component to update
     * @param commitIndex        specifies if the search index should be committed (an expensive operation)
     * @return a Component
     */
    public Component updateComponent(Component transientComponent, boolean commitIndex) {
        final Component component = getObjectByUuid(Component.class, transientComponent.getUuid());
        component.setName(transientComponent.getName());
        component.setVersion(transientComponent.getVersion());
        component.setGroup(transientComponent.getGroup());
        component.setFilename(transientComponent.getFilename());
        component.setMd5(transientComponent.getMd5());
        component.setSha1(transientComponent.getSha1());
        component.setSha256(transientComponent.getSha256());
        component.setSha512(transientComponent.getSha512());
        component.setSha3_256(transientComponent.getSha3_256());
        component.setSha3_512(transientComponent.getSha3_512());
        component.setDescription(transientComponent.getDescription());
        component.setCopyright(transientComponent.getCopyright());
        component.setLicense(transientComponent.getLicense());
        component.setLicenseExpression(transientComponent.getLicenseExpression());
        component.setLicenseUrl(transientComponent.getLicenseUrl());
        component.setResolvedLicense(transientComponent.getResolvedLicense());
        component.setParent(transientComponent.getParent());
        component.setCpe(transientComponent.getCpe());
        component.setPurl(transientComponent.getPurl());
        component.setPurlCoordinates(component.getPurl());
        component.setInternal(transientComponent.isInternal());
        component.setAuthors(transientComponent.getAuthors());
        component.setSupplier(transientComponent.getSupplier());
        component.setExternalReferences(transientComponent.getExternalReferences());
        final Component result = persist(component);
        return result;
    }

    /**
     * Returns a list of components by matching its identity information.
     *
     * @param project the Project the component is a dependency of
     * @param cid     the identity values of the component
     * @return a List of Component objects, or null if not found
     */
    @SuppressWarnings("unchecked")
    public List<Component> matchIdentity(final Project project, final ComponentIdentity cid) {
        final Pair<String, Map<String, Object>> queryFilterParamsPair = buildComponentIdentityQuery(project, cid);
        final Query<Component> query = pm.newQuery(Component.class, queryFilterParamsPair.getLeft());
        return (List<Component>) query.executeWithMap(queryFilterParamsPair.getRight());
    }

    private static Pair<String, Map<String, Object>> buildComponentIdentityQuery(final Project project, final ComponentIdentity cid) {
        String purlString = null;
        String purlCoordinates = null;
        if (cid.getPurl() != null) {
            try {
                final PackageURL purl = cid.getPurl();
                purlString = cid.getPurl().canonicalize();
                purlCoordinates = new PackageURL(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion(), null, null).canonicalize();
            } catch (MalformedPackageURLException e) { // throw it away
            }
        }

        final var filterParts = new ArrayList<String>();
        final var params = new HashMap<String, Object>();

        if (purlString != null) {
            filterParts.add("purl == :purl");
            params.put("purl", purlString);
        }
        if (purlCoordinates != null) {
            filterParts.add("purlCoordinates == :purlCoordinates");
            params.put("purlCoordinates", purlCoordinates);
        }
        if (cid.getCpe() != null) {
            filterParts.add("cpe == :cpe");
            params.put("cpe", cid.getCpe());
        }
        if (cid.getSwidTagId() != null) {
            filterParts.add("swidTagId == :swidTagId");
            params.put("swidTagId", cid.getSwidTagId());
        }

        final var coordinatesFilterParts = new ArrayList<String>();
        if (cid.getGroup() != null) {
            coordinatesFilterParts.add("group == :group");
            params.put("group", cid.getGroup());
        } else {
            coordinatesFilterParts.add("group == null");
        }
        if (cid.getName() != null) {
            coordinatesFilterParts.add("name == :name");
            params.put("name", cid.getName());
        } else {
            coordinatesFilterParts.add("name == null");
        }
        if (cid.getVersion() != null) {
            coordinatesFilterParts.add("version == :version");
            params.put("version", cid.getVersion());
        } else {
            coordinatesFilterParts.add("version == null");
        }
        filterParts.add("(%s)".formatted(String.join(" && ", coordinatesFilterParts)));

        if (project == null) {
            final String filter = String.join(" || ", filterParts);
            return Pair.of(filter, params);
        }

        final String filter = "project == :project && (%s)".formatted(String.join(" || ", filterParts));
        params.put("project", project);
        return Pair.of(filter, params);
    }

    public Map<String, Component> getDependencyGraphForComponents(Project project, List<Component> components) {
        Map<String, Component> dependencyGraph = new HashMap<>();
        if (project.getDirectDependencies() == null || project.getDirectDependencies().isBlank()) {
            return dependencyGraph;
        }

        for(Component component : components) {
            dependencyGraph.put(component.getUuid().toString(), component);
            getParentDependenciesOfComponent(project, component, dependencyGraph);
        }
        if (!dependencyGraph.isEmpty()){
            getRootDependencies(dependencyGraph, project);
            getDirectDependenciesForPathDependencies(dependencyGraph);
        }

        final var packagePurlByComponentUuid = new HashMap<String, String>();
        for (final var entry : dependencyGraph.entrySet()) {
            final String componentUuid = entry.getKey();
            final Component component = entry.getValue();

            if (component.getPurl() != null) {
                packagePurlByComponentUuid.put(
                        componentUuid,
                        PurlUtil.purlPackageOnly(component.getPurl()));
            }
        }

        final var latestVersionByPackagePurl = new HashMap<String, String>();
        if (!packagePurlByComponentUuid.isEmpty()) {
            final List<PackageMetadata> packageMetadataList = withJdbiHandle(
                    handle -> new PackageMetadataDao(handle).getAll(
                            new HashSet<>(packagePurlByComponentUuid.values())));
            for (final PackageMetadata packageMetadata : packageMetadataList) {
                if (packageMetadata.latestVersion() != null) {
                    latestVersionByPackagePurl.put(packageMetadata.purl().canonicalize(), packageMetadata.latestVersion());
                }
            }
        }

        // Reduce size of JSON response
        for (final Map.Entry<String, Component> entry : dependencyGraph.entrySet()) {
            final Component transientComponent = new Component();
            transientComponent.setUuid(entry.getValue().getUuid());
            transientComponent.setName(entry.getValue().getName());
            transientComponent.setVersion(entry.getValue().getVersion());
            transientComponent.setPurl(entry.getValue().getPurl());
            transientComponent.setPurlCoordinates(entry.getValue().getPurlCoordinates());
            transientComponent.setDependencyGraph(entry.getValue().getDependencyGraph());
            transientComponent.setExpandDependencyGraph(entry.getValue().isExpandDependencyGraph());
            final String packagePurl = packagePurlByComponentUuid.get(entry.getKey());
            if (packagePurl != null) {
                final String latestVersion = latestVersionByPackagePurl.get(packagePurl);
                if (latestVersion != null) {
                    final var transientRepoMetaComponent = new RepositoryMetaComponent();
                    transientRepoMetaComponent.setLatestVersion(latestVersion);
                    transientComponent.setRepositoryMeta(transientRepoMetaComponent);
                }
            }
            dependencyGraph.put(entry.getKey(), transientComponent);
        }
        return dependencyGraph;
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link Component} UUID.
     *
     * @param uuids a list of {@link Component} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getDependencyGraphByUUID(final List<UUID> uuids) {
        final Query<Component> query = this.getObjectsByUuidsQuery(Component.class, uuids);
        query.setResult("uuid, name, version, purl, directDependencies, null");
        return List.copyOf(query.executeResultList(DependencyGraphResponse.class));
    }

    private void getParentDependenciesOfComponent(Project project, Component childComponent, Map<String, Component> dependencyGraph) {
        final Query<Component> query = pm.newQuery(Component.class, "directDependencies.jsonbContains(:child) && project == :project");
        List<Component> parentComponents = (List<Component>) query.executeWithArray("[{\"uuid\":\"%s\"}]".formatted(childComponent.getUuid()), project);
        for (Component parentComponent : parentComponents) {
            parentComponent.setExpandDependencyGraph(true);
            if(parentComponent.getDependencyGraph() == null) {
                parentComponent.setDependencyGraph(new HashSet<>());
            }
            parentComponent.getDependencyGraph().add(childComponent.getUuid().toString());
            if (!dependencyGraph.containsKey(parentComponent.getUuid().toString())) {
                dependencyGraph.put(parentComponent.getUuid().toString(), parentComponent);
                getParentDependenciesOfComponent(project, parentComponent, dependencyGraph);
            }
        }
    }

    private void getRootDependencies(Map<String, Component> dependencyGraph, Project project) {
        JsonArray directDependencies = Json.createReader(new StringReader(project.getDirectDependencies())).readArray();
        for (JsonValue directDependency : directDependencies) {
            String uuid = directDependency.asJsonObject().getString("uuid");
            if (!dependencyGraph.containsKey(uuid)) {
                Component component = this.getObjectByUuid(Component.class, uuid);
                dependencyGraph.put(uuid, component);
            }
        }
        getDirectDependenciesForPathDependencies(dependencyGraph);
    }

    private void getDirectDependenciesForPathDependencies(Map<String, Component> dependencyGraph) {
        Map<String, Component> addToDependencyGraph = new HashMap<>();
        for (Component component : dependencyGraph.values()) {
            if (component.getDirectDependencies() != null && !component.getDirectDependencies().isEmpty()) {
                JsonArray directDependencies = Json.createReader(new StringReader(component.getDirectDependencies())).readArray();
                for (JsonValue directDependency : directDependencies) {
                    if (component.getDependencyGraph() == null) {
                        component.setDependencyGraph(new HashSet<>());
                    }
                    String uuid = directDependency.asJsonObject().getString("uuid");
                    if (!dependencyGraph.containsKey(uuid) && !addToDependencyGraph.containsKey(uuid)) {
                        Component childNode = this.getObjectByUuid(Component.class, uuid);
                        addToDependencyGraph.put(childNode.getUuid().toString(), childNode);
                        component.getDependencyGraph().add(childNode.getUuid().toString());
                    } else {
                        component.getDependencyGraph().add(uuid);
                    }
                }
            }
        }
        dependencyGraph.putAll(addToDependencyGraph);
    }

    public List<Component> getComponentsByPurl(String purl) {
        try(final Query<Component> query = pm.newQuery(Component.class, "purl == :purl")) {
            query.setParameters(purl);
            return List.copyOf(query.executeResultList(Component.class));
        } catch(Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    @Override
    public List<ComponentProperty> getComponentProperties(final Component component, final String groupName, final String propertyName) {
        final Query<ComponentProperty> query = pm.newQuery(ComponentProperty.class);
        query.setFilter("component == :component && groupName == :groupName && propertyName == :propertyName");
        query.setParameters(component, groupName, propertyName);
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    @Override
    public List<ComponentProperty> getComponentProperties(final Component component) {
        final Query<ComponentProperty> query = pm.newQuery(ComponentProperty.class);
        query.setFilter("component == :component");
        query.setParameters(component);
        query.setOrdering("groupName ASC, propertyName ASC, id ASC");
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    @Override
    public ComponentProperty createComponentProperty(final Component component,
                                                     final String groupName,
                                                     final String propertyName,
                                                     final String propertyValue,
                                                     final PropertyType propertyType,
                                                     final String description) {
        final ComponentProperty property = new ComponentProperty();
        property.setComponent(component);
        property.setGroupName(groupName);
        property.setPropertyName(propertyName);
        property.setPropertyValue(propertyValue);
        property.setPropertyType(propertyType);
        property.setDescription(description);
        return persist(property);
    }

    @Override
    public long deleteComponentPropertyByUuid(final Component component, final UUID uuid) {
        final Query<ComponentProperty> query = pm.newQuery(ComponentProperty.class);
        query.setFilter("component == :component && uuid == :uuid");
        try {
            return query.deletePersistentAll(component, uuid);
        } finally {
            query.closeAll();
        }
    }

    public void synchronizeComponentProperties(final Component component, final List<ComponentProperty> properties) {
        assertPersistent(component, "component must be persistent");

        if (properties == null || properties.isEmpty()) {
            // TODO: We currently remove all existing properties that are no longer included in the BOM.
            //   This is to stay consistent with the BOM being the source of truth. However, this may feel
            //   counter-intuitive to some users, who might expect their manual changes to persist.
            //   If we want to support that, we need a way to track which properties were added and / or
            //   modified manually.
            if (component.getProperties() != null && !component.getProperties().isEmpty()) {
                pm.deletePersistentAll(component.getProperties());
                component.setProperties(null);
            }

            return;
        }

        // Map and de-duplicate incoming properties by their identity.
        final var incomingPropertyIdentitiesSeen = new HashSet<ComponentProperty.Identity>();
        final var incomingPropertiesByIdentity = properties.stream()
                .peek(property -> assertNonPersistent(property, "property must not be persistent"))
                .filter(property -> incomingPropertyIdentitiesSeen.add(new ComponentProperty.Identity(property)))
                .collect(Collectors.toMap(ComponentProperty.Identity::new, Function.identity()));

        if (component.getProperties() == null || component.getProperties().isEmpty()) {
            for (final ComponentProperty property : incomingPropertiesByIdentity.values()) {
                property.setComponent(component);
                pm.makePersistent(property);
                component.addProperty(property);
            }

            return;
        }

        // Group properties by group, name, and value. Because CycloneDX supports duplicate
        // property names, uniqueness can only be determined by also considering the value.
        final var existingPropertyIdentitiesSeen = new HashSet<ComponentProperty.Identity>();
        final var existingDuplicateProperties = new HashSet<ComponentProperty>();
        final var existingPropertiesByIdentity = component.getProperties().stream()
                // The legacy BOM processing in <= 4.11.x allowed duplicates to be persisted.
                // Collectors#toMap fails upon encounter of duplicate keys.
                // Prevent existing duplicates from breaking this.
                // https://github.com/DependencyTrack/dependency-track/issues/4027
                .filter(property -> {
                    final var identity = new ComponentProperty.Identity(property);
                    final boolean isUnique = existingPropertyIdentitiesSeen.add(identity);
                    if (!isUnique) {
                        existingDuplicateProperties.add(property);
                    }
                    return isUnique;
                })
                .collect(Collectors.toMap(ComponentProperty.Identity::new, Function.identity()));

        if (!existingDuplicateProperties.isEmpty()) {
            pm.deletePersistentAll(existingDuplicateProperties);
            component.getProperties().removeAll(existingDuplicateProperties);
        }

        final var propertyIdentities = new HashSet<ComponentProperty.Identity>();
        propertyIdentities.addAll(existingPropertiesByIdentity.keySet());
        propertyIdentities.addAll(incomingPropertiesByIdentity.keySet());

        for (final ComponentProperty.Identity identity : propertyIdentities) {
            final ComponentProperty existingProperty = existingPropertiesByIdentity.get(identity);
            final ComponentProperty incomingProperty = incomingPropertiesByIdentity.get(identity);

            if (existingProperty == null) {
                incomingProperty.setComponent(component);
                pm.makePersistent(incomingProperty);
                component.addProperty(incomingProperty);
            } else if (incomingProperty == null) {
                pm.deletePersistent(existingProperty);
                component.getProperties().remove(existingProperty);
            }
        }
    }

    /**
     * @since 5.0.0
     */
    @Override
    public void synchronizeComponentOccurrences(final Component component, final Collection<ComponentOccurrence> occurrences) {
        assertPersistent(component, "component must be persistent");

        // No incoming occurrences. Remove existing occurrences from the component if there are any.
        if (occurrences == null || occurrences.isEmpty()) {
            if (component.getOccurrences() != null && !component.getOccurrences().isEmpty()) {
                pm.deletePersistentAll(component.getProperties());
                component.setOccurrences(null);
            }

            return;
        }

        // Map and de-duplicate incoming occurrences by their identity.
        final var incomingOccurrenceIdentitiesSeen = new HashSet<ComponentOccurrence.Identity>();
        final var incomingOccurrenceByIdentity = occurrences.stream()
                .peek(occurrence -> assertNonPersistent(occurrence, "occurrence must not be persistent"))
                .filter(occurrence -> incomingOccurrenceIdentitiesSeen.add(ComponentOccurrence.Identity.of(occurrence)))
                .collect(Collectors.toMap(ComponentOccurrence.Identity::of, Function.identity(), (left, right) -> left));

        // No existing occurrences. Add them all.
        if (component.getOccurrences() == null || component.getOccurrences().isEmpty()) {
            for (final ComponentOccurrence occurrence : incomingOccurrenceByIdentity.values()) {
                occurrence.setComponent(component);
                pm.makePersistent(occurrence);
                component.addOccurrence(occurrence);
            }

            return;
        }

        // Map existing occurrences by their identity.
        final var existingOccurrenceIdentitiesSeen = new HashSet<ComponentOccurrence.Identity>();
        final var existingOccurrenceByIdentity = component.getOccurrences().stream()
                .filter(occurrence -> existingOccurrenceIdentitiesSeen.add(ComponentOccurrence.Identity.of(occurrence)))
                .collect(Collectors.toMap(ComponentOccurrence.Identity::of, Function.identity()));

        final var identities = new HashSet<ComponentOccurrence.Identity>();
        identities.addAll(existingOccurrenceByIdentity.keySet());
        identities.addAll(incomingOccurrenceByIdentity.keySet());

        for (final ComponentOccurrence.Identity identity : identities) {
            final ComponentOccurrence existingOccurrence = existingOccurrenceByIdentity.get(identity);
            final ComponentOccurrence incomingOccurrence = incomingOccurrenceByIdentity.get(identity);

            if (existingOccurrence == null) {
                incomingOccurrence.setComponent(component);
                pm.makePersistent(incomingOccurrence);
                component.addOccurrence(incomingOccurrence);
            } else if (incomingOccurrence == null) {
                component.getOccurrences().remove(existingOccurrence);
                pm.deletePersistent(existingOccurrence);
            }
        }
    }

    private void populateMetrics(final Collection<Component> components) {
        final Map<Long, Component> componentById = components.stream()
                .collect(Collectors.toMap(Component::getId, Function.identity()));
        final List<DependencyMetrics> metricsList = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentDependencyMetrics(componentById.keySet()));
        for (final DependencyMetrics metrics : metricsList) {
            final var component = componentById.get(metrics.getComponentId());
            if (component != null) {
                component.setMetrics(metrics);
            }
        }
    }

    private void populateRepositoryMetadata(final Collection<Component> components) {
        final Map<String, List<Component>> componentsByPurlPackage = components.stream()
                .filter(component -> component.getPurl() != null)
                .filter(component -> RepositoryType.UNSUPPORTED != RepositoryType.resolve(component.getPurl()))
                .collect(Collectors.groupingBy(component -> PurlUtil.purlPackageOnly(component.getPurl())));
        if (componentsByPurlPackage.isEmpty()) {
            return;
        }

        final List<PackageMetadata> packageMetadataList = withJdbiHandle(
                handle -> new PackageMetadataDao(handle).getAll(componentsByPurlPackage.keySet()));
        for (final PackageMetadata pm : packageMetadataList) {
            final List<Component> matchingComponents = componentsByPurlPackage.get(pm.purl().canonicalize());
            if (matchingComponents != null) {
                final var repoMetaComponent = RepositoryMetaComponent.of(pm);
                for (final Component component : matchingComponents) {
                    component.setRepositoryMeta(repoMetaComponent);
                }
            }
        }
    }

}
