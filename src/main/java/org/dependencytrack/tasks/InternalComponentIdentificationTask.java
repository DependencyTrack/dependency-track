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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.datanucleus.PropertyNames;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentificationUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Subscriber task that identifies internal components throughout the entire portfolio.
 *
 * @author nscuro
 * @since 3.7.0
 */
public class InternalComponentIdentificationTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalComponentIdentificationTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof InternalComponentIdentificationEvent) {
            LOGGER.info("Starting internal component identification");
            final Instant startTime = Instant.now();
            try {
                analyze();
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while identifying internal components", ex);
            }
            LOGGER.info("Internal component identification completed in "
                    + DateFormatUtils.format(Duration.between(startTime, Instant.now()).toMillis(), "mm:ss:SS"));
        }
    }

    private void analyze() throws Exception {
        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            // Disable the DataNucleus L2 cache for this persistence manager.
            // The cache will hold references to the queried objects, preventing them
            // from being garbage collected. This is not required the case of this task.
            pm.setProperty(PropertyNames.PROPERTY_CACHE_L2_TYPE, "none");

            List<Component> components = fetchNextComponentsPage(pm, null);
            while (!components.isEmpty()) {
                for (final Component component : components) {
                    String coordinates = component.getName();
                    if (StringUtils.isNotBlank(component.getGroup())) {
                        coordinates = component.getGroup() + ":" + coordinates;
                    }

                    final boolean internal = InternalComponentIdentificationUtil.isInternalComponent(component, qm);
                    if (internal) {
                        LOGGER.debug("Component " + coordinates + " (" + component.getUuid() + ") was identified to be internal");
                    }

                    if (component.isInternal() != internal) {
                        if (internal) {
                            LOGGER.info("Component " + coordinates + " (" + component.getUuid()
                                    + ") was identified to be internal. It was previously not an internal component.");
                        } else {
                            LOGGER.info("Component " + coordinates + " (" + component.getUuid()
                                    + ") was previously identified as internal. It is no longer identified as internal.");
                        }
                    }

                    if (component.isInternal() != internal) {
                        final Transaction trx = pm.currentTransaction();
                        try {
                            trx.begin();
                            component.setInternal(internal);
                            trx.commit();
                        } finally {
                            if (trx.isActive()) {
                                trx.rollback();
                            }
                        }
                    }
                }

                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(pm, lastId);
            }
        }
    }

    /**
     * Efficiently page through all components using keyset pagination.
     *
     * @param pm     The {@link PersistenceManager} to use
     * @param lastId ID of the last {@link Component} in the previous result set, or {@code null} if this is the first invocation
     * @return A {@link List} representing a page of up to {@code 500} {@link Component}s
     * @throws Exception When closing the query failed
     * @see <a href="https://use-the-index-luke.com/no-offset">Keyset pagination</a>
     */
    private List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            if (lastId != null) {
                query.setFilter("id < :lastId");
                query.setParameters(lastId);
            }
            query.setOrdering("id DESC");
            query.setRange(0, 500);
            query.getFetchPlan().setGroup(Component.FetchGroup.INTERNAL_IDENTIFICATION.name());
            return List.copyOf(query.executeList());
        }
    }

}
