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

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import org.dependencytrack.event.CloneProjectEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import java.util.UUID;

public class CloneProjectTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(CloneProjectTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof CloneProjectEvent) {
            final CloneProjectEvent event = (CloneProjectEvent)e;
            final CloneProjectRequest request = event.getRequest();
            LOGGER.info("Cloning project: " + request.getProject());
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.clone(UUID.fromString(request.getProject()),
                        request.getVersion(), request.includeTags(), request.includeProperties(),
                        request.includeComponents(), request.includeServices(), request.includeAuditHistory());
                LOGGER.info("Cloned project: " + request.getProject() + " to " + project.getUuid());
            }
        }
    }
}
