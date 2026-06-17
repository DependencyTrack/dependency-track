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
package org.dependencytrack.tasks;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.model.Component;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Identifies internal components throughout the entire portfolio.
 *
 * @since 5.0.0
 */
@ActivitySpec(name = "identify-internal-components")
public final class IdentifyInternalComponentsActivity implements Activity<Void, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(IdentifyInternalComponentsActivity.class);

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable Void argument) throws InterruptedException {
        final Instant startTime = Instant.now();
        LOGGER.info("Starting internal component identification");
        final var internalComponentIdentifier = new InternalComponentIdentifier();

        if (!internalComponentIdentifier.hasPatterns() && !internalComponentsExist()) {
            LOGGER.info("""
                    No internal patterns configured, and no components currently
                    marked as internal exist; Nothing to do""");
            return null;
        }

        final var changedInternalStatusByComponentId = new HashMap<Long, Boolean>(250);
        List<Component> components = fetchNextComponentsPage(null);
        while (!components.isEmpty()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all components could be processed");
            }
            ctx.maybeHeartbeat();

            for (final Component component : components) {
                String coordinates = component.getName();
                if (StringUtils.isNotBlank(component.getGroup())) {
                    coordinates = component.getGroup() + ":" + coordinates;
                }

                final boolean internal = internalComponentIdentifier.isInternal(component);
                if (internal && LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Component {} ({}) was identified to be internal", coordinates, component.getUuid());
                }

                if (component.isInternal() != internal) {
                    if (internal) {
                        LOGGER.info("Component {} ({}) was identified to be internal. It was previously not an internal component.", coordinates, component.getUuid());
                    } else {
                        LOGGER.info("Component {} ({}) was previously identified as internal. It is no longer identified as internal.", coordinates, component.getUuid());
                    }

                    changedInternalStatusByComponentId.put(component.getId(), internal);
                }
            }

            updateInternalStatuses(changedInternalStatusByComponentId);
            changedInternalStatusByComponentId.clear();

            final long lastId = components.getLast().getId();
            components = fetchNextComponentsPage(lastId);
        }

        LOGGER.info("Internal component identification completed in {}", DateFormatUtils.format(Duration.between(startTime, Instant.now()).toMillis(), "mm:ss:SS"));
        return null;
    }

    private boolean internalComponentsExist() {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT EXISTS(SELECT 1 FROM "COMPONENT" WHERE "INTERNAL")
                        """)
                .define(ATTRIBUTE_QUERY_NAME, "%s#internalComponentsExist".formatted(getClass().getSimpleName()))
                .mapTo(Boolean.class)
                .one());
    }

    private List<Component> fetchNextComponentsPage(final Long lastId) {
        return withJdbiHandle(handle -> handle.createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="lastId" type="boolean" -->
                        SELECT "ID"
                             , "GROUP"
                             , "NAME"
                             , "INTERNAL"
                             , "UUID"
                          FROM "COMPONENT"
                        <#if lastId>
                         WHERE "ID" < :lastId
                        </#if>
                         ORDER BY "ID" DESC
                         FETCH NEXT 1000 ROWS ONLY
                        """)
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .define(ATTRIBUTE_QUERY_NAME, "%s#fetchNextComponentsPage".formatted(getClass().getSimpleName()))
                .bind("lastId", lastId)
                .defineNamedBindings()
                .mapToBean(Component.class)
                .list());
    }

    private void updateInternalStatuses(final Map<Long, Boolean> internalStatusByComponentId) {
        if (internalStatusByComponentId.isEmpty()) {
            return;
        }

        useJdbiTransaction(handle -> {
            final PreparedBatch batch = handle.prepareBatch("""
                    UPDATE "COMPONENT"
                       SET "INTERNAL" = :internal
                     WHERE "ID" = :id
                    """);

            internalStatusByComponentId.forEach((componentId, internalStatus) -> {
                batch.bind("id", componentId);
                batch.bind("internal", internalStatus);
                batch.add();
            });

            batch
                    .define(ATTRIBUTE_QUERY_NAME, "%s#updateInternalStatuses".formatted(getClass().getSimpleName()))
                    .execute();
        });
    }

}
