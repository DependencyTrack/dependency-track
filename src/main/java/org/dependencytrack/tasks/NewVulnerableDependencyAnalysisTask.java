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
import org.dependencytrack.event.NewVulnerableDependencyAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

/**
 * A {@link Subscriber} task that evaluates whether components qualify for
 * a {@link org.dependencytrack.notification.NotificationGroup#NEW_VULNERABLE_DEPENDENCY} notification.
 *
 * @since 4.6.0
 */
public class NewVulnerableDependencyAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NewVulnerableDependencyAnalysisTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final NewVulnerableDependencyAnalysisEvent event) {
            for (Component component : event.components()) {
                try (final var qm = new QueryManager()) {
                    component = qm.getObjectById(Component.class, component.getId());
                    LOGGER.debug("Analyzing notification criteria for component " + component.getUuid());
                    NotificationUtil.analyzeNotificationCriteria(qm, component);
                } catch (Exception ex) {
                    LOGGER.error("An unknown error occurred while analyzing notification criteria for component " + component.getUuid(), ex);
                }
            }
        }
    }

}
