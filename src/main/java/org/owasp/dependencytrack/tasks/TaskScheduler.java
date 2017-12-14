/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.tasks;

import alpine.event.LdapSyncEvent;
import alpine.tasks.AlpineTaskScheduler;
import org.owasp.dependencytrack.event.DependencyCheckEvent;
import org.owasp.dependencytrack.event.MetricsUpdateEvent;
import org.owasp.dependencytrack.event.NistMirrorEvent;
import org.owasp.dependencytrack.event.NspMirrorEvent;
import org.owasp.dependencytrack.event.VulnDbSyncEvent;

/**
 * A Singleton implementation of {@link AlpineTaskScheduler} that configures scheduled and repeatable tasks.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class TaskScheduler extends AlpineTaskScheduler {

    // Holds an instance of TaskScheduler
    private static final TaskScheduler INSTANCE = new TaskScheduler();

    /**
     * Private constructor.
     */
    private TaskScheduler() {

        // Creates a new event that executes every 6 hours (21600000) after an initial 10 second (10000) delay
        scheduleEvent(new LdapSyncEvent(), 10000, 21600000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 10 second (10000) delay
        scheduleEvent(new NspMirrorEvent(), 10000, 86400000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 1 minute (60000) delay
        scheduleEvent(new NistMirrorEvent(), 60000, 86400000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 1 minute (60000) delay
        scheduleEvent(new VulnDbSyncEvent(), 60000, 86400000);

        // Creates a new event that executes every 1 hour (3600000) after an initial 10 second (10000) delay
        scheduleEvent(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO), 10000, 3600000);

        // Creates a new event that executes every 1 hour (3600000) after an initial 10 second (10000) delay
        scheduleEvent(new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY), 10000, 3600000);

        // Creates a new event that executes every 6 hours (21600000) after an initial 1 minute (60000) delay
        scheduleEvent(new DependencyCheckEvent(DependencyCheckEvent.Action.ANALYZE), 60000, 21600000);

        // Creates a new event that executes every 6 hours (21600000) after an initial 10 second (10000) delay
        scheduleEvent(new DependencyCheckEvent(DependencyCheckEvent.Action.UPDATE_ONLY), 10000, 21600000);
    }

    /**
     * Return an instance of the TaskScheduler instance.
     * @return a TaskScheduler instance
     */
    public static TaskScheduler getInstance() {
        return INSTANCE;
    }

}
