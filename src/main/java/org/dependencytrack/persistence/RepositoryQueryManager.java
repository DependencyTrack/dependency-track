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

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.security.crypto.DataEncryption;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class RepositoryQueryManager extends QueryManager implements IQueryManager {
    private static final Logger LOGGER = Logger.getLogger(RepositoryQueryManager.class);


    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    RepositoryQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    RepositoryQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }


    /**
     * Returns a list of all repositories.
     *
     * @return a List of Repositories
     */
    public PaginatedResult getRepositories() {
        final Query<Repository> query = pm.newQuery(Repository.class);
        if (orderBy == null) {
            query.setOrdering("type asc, identifier asc");
        }
        if (filter != null) {
            query.setFilter("identifier.toLowerCase().matches(:identifier)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a list of all repositories
     * This method if designed NOT to provide paginated results.
     *
     * @return a List of Repositories
     */
    public List<Repository> getAllRepositories() {
        final Query<Repository> query = pm.newQuery(Repository.class);
        query.setOrdering("type asc, identifier asc");
        return query.executeList();
    }

    /**
     * Returns a list of repositories by it's type.
     *
     * @param type the type of repository (required)
     * @return a List of Repository objects
     */
    public PaginatedResult getRepositories(RepositoryType type) {
        final Query<Repository> query = pm.newQuery(Repository.class, "type == :type");
        if (orderBy == null) {
            query.setOrdering("identifier asc");
        }
        return execute(query, type);
    }

    /**
     * Returns a list of repositories by it's type in the order in which the repository should be used in resolution.
     * This method if designed NOT to provide paginated results.
     *
     * @param type the type of repository (required)
     * @return a List of Repository objects
     */
    @SuppressWarnings("unchecked")
    public List<Repository> getAllRepositoriesOrdered(RepositoryType type) {
        final Query<Repository> query = pm.newQuery(Repository.class, "type == :type");
        query.setOrdering("resolutionOrder asc");
        return (List<Repository>) query.execute(type);
    }

    /**
     * Determines if the repository exists in the database.
     *
     * @param type       the type of repository (required)
     * @param identifier the repository identifier
     * @return true if object exists, false if not
     */
    public boolean repositoryExist(RepositoryType type, String identifier) {
        final Query<Repository> query = pm.newQuery(Repository.class, "type == :type && identifier == :identifier");
        query.setRange(0, 1);
        return singleResult(query.execute(type, identifier)) != null;
    }

    /**
     * Creates a new Repository.
     *
     * @param type                     the type of repository
     * @param identifier               a unique (to the type) identifier for the repo
     * @param url                      the URL to the repository
     * @param enabled                  if the repo is enabled or not
     * @param internal                 if the repo is internal or not
     * @param isAuthenticationRequired if the repository needs authentication or not
     * @param username                 the username to access the (authenticated) repository with
     * @param password                 the password to access the (authenticated) repository with
     * @param bearerToken              the token to access the (authenticated) repository with
     * @return the created Repository
     */
    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled, boolean internal, boolean isAuthenticationRequired, String username, String password, String bearerToken) {
        if (repositoryExist(type, identifier)) {
            return null;
        }
        int order = 0;
        final List<Repository> existingRepos = getAllRepositoriesOrdered(type);
        if (existingRepos != null && !existingRepos.isEmpty()) {
            for (final Repository existing : existingRepos) {
                if (existing.getResolutionOrder() > order) {
                    order = existing.getResolutionOrder();
                }
            }
        }
        final Repository repo = new Repository();
        repo.setType(type);
        repo.setIdentifier(identifier);
        repo.setUrl(url);
        repo.setResolutionOrder(order + 1);
        repo.setEnabled(enabled);
        repo.setInternal(internal);
        repo.setAuthenticationRequired(isAuthenticationRequired);
        if (Boolean.TRUE.equals(isAuthenticationRequired) && (username != null || password != null || bearerToken != null)) {
            repo.setUsername(StringUtils.trimToNull(username));
            String msg = "password";
            try {
                if (password != null) {
                    repo.setPassword(DataEncryption.encryptAsString(password));
                }
                msg = "bearerToken";
                if (bearerToken != null) {
                    repo.setBearerToken(DataEncryption.encryptAsString(bearerToken));
                }
            } catch (Exception e) {
                LOGGER.error("An error occurred while saving %s in encrypted state".formatted(msg));
            }

        }
        return persist(repo);
    }

    /**
     * Updates an existing Repository.
     *
     * @param uuid                   the uuid of the repository to update
     * @param identifier             the identifier of the repository
     * @param url                    a url of the repository
     * @param internal               specifies if the repository is internal
     * @param authenticationRequired if the repository needs authentication or not
     * @param username               the username to access the (authenticated) repository with
     * @param password               the password to access the (authenticated) repository with
     * @param bearerToken            the bearer token to access the (authenticated) repository with
     * @param enabled                specifies if the repository is enabled
     * @return the updated Repository
     */
    public Repository updateRepository(UUID uuid, String identifier, String url, boolean internal, boolean authenticationRequired, String username, String password, String bearerToken, boolean enabled) {
        final Repository repository = getObjectByUuid(Repository.class, uuid);
        repository.setIdentifier(identifier);
        repository.setUrl(url);
        repository.setInternal(internal);
        repository.setAuthenticationRequired(authenticationRequired);
        if (!authenticationRequired) {
            repository.setUsername(null);
            repository.setPassword(null);
            repository.setBearerToken(null);
        } else {
            repository.setUsername(username);
            repository.setPassword(password);
            repository.setBearerToken(bearerToken);
        }

        repository.setEnabled(enabled);
        return persist(repository);
    }

    /**
     * Returns a RepositoryMetaComponent object from the specified type, group, and name.
     *
     * @param repositoryType the type of repository
     * @param namespace      the Package URL namespace of the meta component
     * @param name           the Package URL name of the meta component
     * @return a RepositoryMetaComponent object, or null if not found
     */
    public RepositoryMetaComponent getRepositoryMetaComponent(RepositoryType repositoryType, String
            namespace, String name) {
        final Query<RepositoryMetaComponent> query = pm.newQuery(RepositoryMetaComponent.class);
        query.setFilter("repositoryType == :repositoryType && namespace == :namespace && name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(repositoryType, namespace, name));
    }

    /**
     * Synchronizes a RepositoryMetaComponent, updating it if it needs updating, or creating it if it doesn't exist.
     *
     * @param transientRepositoryMetaComponent the RepositoryMetaComponent object to synchronize
     * @return a synchronized RepositoryMetaComponent object
     */
    public synchronized RepositoryMetaComponent synchronizeRepositoryMetaComponent(
            final RepositoryMetaComponent transientRepositoryMetaComponent) {
        final RepositoryMetaComponent metaComponent = getRepositoryMetaComponent(transientRepositoryMetaComponent.getRepositoryType(),
                transientRepositoryMetaComponent.getNamespace(), transientRepositoryMetaComponent.getName());
        if (metaComponent != null) {
            metaComponent.setRepositoryType(transientRepositoryMetaComponent.getRepositoryType());
            metaComponent.setNamespace(transientRepositoryMetaComponent.getNamespace());
            metaComponent.setLastCheck(transientRepositoryMetaComponent.getLastCheck());
            metaComponent.setLatestVersion(transientRepositoryMetaComponent.getLatestVersion());
            metaComponent.setName(transientRepositoryMetaComponent.getName());
            metaComponent.setPublished(transientRepositoryMetaComponent.getPublished());
            return persist(metaComponent);
        } else {
            return persist(transientRepositoryMetaComponent);
        }
    }

    /**
     * Returns a list of {@link RepositoryMetaComponent} objects from the specified type, group, and name.
     *
     * @param list a list of {@link RepositoryQueryManager.RepositoryMetaComponentSearch} used to filter
     * @return a List of {@link RepositoryMetaComponent} objects
     * @since 4.9.0
     */
    public List<RepositoryMetaComponent> getRepositoryMetaComponents(final List<RepositoryQueryManager.RepositoryMetaComponentSearch> list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }

        final Query<RepositoryMetaComponent> query = pm.newQuery(RepositoryMetaComponent.class);

        // Dynamically build the filter string and populate the parameters
        final String filterTemplate = "(repositoryType == :%s && name == :%s && namespace == :%s)";

        // List with all the filters
        final List<String> filters = new ArrayList<>(list.size());

        // Map with all the parameters
        final Map<String, Object> params = new HashMap<>(list.size() * 3);

        final String repositoryTypeTemplate = "repositoryType_%d";
        final String nameTemplate = "name_%d";
        final String namespaceTemplate = "namespace_%d";

        String repositoryTypeTemplatePopulate;
        String nameTemplatePopulate;
        String namespaceTemplatePopulate;

        for (int i = 0; i < list.size(); i++) {
            // Create the template strings for this iteration
            repositoryTypeTemplatePopulate = String.format(repositoryTypeTemplate, i);
            namespaceTemplatePopulate = String.format(namespaceTemplate, i);
            nameTemplatePopulate = String.format(nameTemplate, i);

            // Add the filter to the list
            filters.add(String.format(filterTemplate, repositoryTypeTemplatePopulate, nameTemplatePopulate, namespaceTemplatePopulate));

            // Add the parameters to the map
            params.put(repositoryTypeTemplatePopulate, list.get(i).type());
            params.put(nameTemplatePopulate, list.get(i).name());
            params.put(namespaceTemplatePopulate, list.get(i).namespace());
        }

        // Join all filters with OR operator
        query.setFilter(String.join(" || ", filters));
        query.setNamedParameters(params);
        return query.executeList();
    }


    /**
     * Object used to search for a RepositoryMetaComponent by type, namespace, and name.
     *
     * @author Nathan Mittelette <mittelette.nathan@gmail.com>
     * @since 4.9.0
     */
    public record RepositoryMetaComponentSearch(RepositoryType type, String namespace,
                                                String name) implements Serializable {
    }
}
