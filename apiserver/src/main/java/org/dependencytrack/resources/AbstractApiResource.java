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
package org.dependencytrack.resources;

import alpine.server.resources.AlpineResource;
import org.dependencytrack.api.v2.model.TotalCount;
import org.dependencytrack.api.v2.model.TotalCountType;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.exception.ProjectAccessDeniedException;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.common.MdcKeys.MDC_COMPONENT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
public abstract class AbstractApiResource extends AlpineResource {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * @see #requireAccess(QueryManager, Project, String)
     */
    protected void requireAccess(final QueryManager qm, final Project project) {
        requireAccess(qm, project, null);
    }

    /**
     * Asserts that the authenticated {@link Principal} has access to a given {@link Project}.
     *
     * @param qm      The {@link QueryManager} to use.
     * @param project The {@link Project} to verify access permission for.
     * @param message The message to use if a {@link ProjectAccessDeniedException} is thrown.
     * @throws ProjectAccessDeniedException When the authenticated {@link Principal}
     *                                      does not have access to the given {@link Project}.
     */
    protected void requireAccess(final QueryManager qm, final Project project, final String message) {
        // TODO: Could make sense to cache the result for at least a few seconds.
        //  Frontend and API clients tend to make multiple successive requests targeting
        //  the same project. If we can avoid this overhead for even a few of those
        //  requests, that would already help under high traffic conditions.

        if (!qm.hasAccess(super.getPrincipal(), project)) {
            try (var ignored = new MdcScope(Map.ofEntries(
                    Map.entry(MDC_PROJECT_UUID, project.getUuid().toString()),
                    Map.entry(MDC_PROJECT_NAME, project.getName()),
                    Map.entry(MDC_PROJECT_VERSION, String.valueOf(project.getVersion()))))) {
                logSecurityEvent(logger, SecurityMarkers.SECURITY_FAILURE, "Unauthorized project access attempt");
            }

            throw new ProjectAccessDeniedException(requireNonNullElse(
                    message, "Access to the requested project is forbidden"));
        }
    }

    /**
     * Asserts that the authenticated {@link Principal} has access to the component with a given {@link UUID}.
     *
     * @param jdbiHandle    The {@link Handle} to use.
     * @param componentUuid {@link UUID} of the component to verify access permission for.
     * @throws NoSuchElementException       When no component with the given {@link UUID} exists.
     * @throws ProjectAccessDeniedException When the authenticated {@link Principal}
     *                                      does not have access to the given {@link Project}.
     */
    protected void requireComponentAccess(final Handle jdbiHandle, final UUID componentUuid) {
        final var dao = jdbiHandle.attach(ComponentDao.class);

        final Boolean isAccessible = dao.isAccessible(componentUuid);
        if (isAccessible == null) {
            throw new NoSuchElementException("Component could not be found");
        } else if (!isAccessible) {
            try (var ignored = new MdcScope(Map.of(MDC_COMPONENT_UUID, componentUuid.toString()))) {
                logSecurityEvent(logger, SecurityMarkers.SECURITY_FAILURE, "Unauthorized project access attempt");
            }

            throw new ProjectAccessDeniedException("Access to the requested project is forbidden");
        }
    }

    /**
     * Asserts that the authenticated {@link Principal} has access to the project with a given {@link UUID}.
     *
     * @param jdbiHandle  The {@link Handle} to use.
     * @param projectUuid {@link UUID} of the project to verify access permission for.
     * @throws NoSuchElementException       When no project with the given {@link UUID} exists.
     * @throws ProjectAccessDeniedException When the authenticated {@link Principal}
     *                                      does not have access to the given {@link Project}.
     */
    protected void requireProjectAccess(final Handle jdbiHandle, final UUID projectUuid) {
        final var dao = jdbiHandle.attach(ProjectDao.class);
        final Boolean isAccessible = dao.isAccessible(projectUuid);
        if (isAccessible == null) {
            throw new NoSuchElementException("Project could not be found");
        } else if (!isAccessible) {
            try (var ignored = new MdcScope(Map.of(MDC_PROJECT_UUID, projectUuid.toString()))) {
                logSecurityEvent(logger, SecurityMarkers.SECURITY_FAILURE, "Unauthorized project access attempt");
            }
            throw new ProjectAccessDeniedException("Access to the requested project is forbidden");
        }
    }

    /**
     * Returns the subset of {@code projects} that the authenticated {@link Principal}
     * has access to. The order of the input is preserved.
     * <p>
     * The intended use is to filter {@link Project} collections embedded in a response payload
     * (e.g. {@link Policy#projects}) prior to serialization, where the persistence layer does
     * not natively apply ACL to the loaded child collection.
     * <p>
     * <strong>This is a stopgap</strong>! The proper remediation is paginated sub-resources,
     * where the listing itself enforces ACL. <strong>Only use this method for legacy endpoints</strong>,
     * do not design new endpoints around this logic!
     *
     * @return Subset of {@code projects} that the authenticated {@link Principal} has access to.
     */
    protected List<Project> filterAccessibleProjects(@Nullable Collection<Project> projects) {
        if (projects == null || projects.isEmpty()) {
            return List.of();
        }

        final Set<UUID> accessibleUuids = withJdbiHandle(
                super.getAlpineRequest(),
                handle -> handle
                        .attach(ProjectDao.class)
                        .getAccessibleProjectUuids(
                                projects.stream()
                                        .map(Project::getUuid)
                                        .collect(Collectors.toSet())));

        return projects.stream()
                .filter(project -> accessibleUuids.contains(project.getUuid()))
                .toList();
    }

    protected @Nullable TotalCount convertTotalCount(Page.@Nullable TotalCount totalCount) {
        if (totalCount == null) {
            return null;
        }

        return TotalCount.builder()
                .count(totalCount.value())
                .type(switch (totalCount.type()) {
                    case AT_LEAST -> TotalCountType.AT_LEAST;
                    case EXACT -> TotalCountType.EXACT;
                })
                .build();
    }

}
