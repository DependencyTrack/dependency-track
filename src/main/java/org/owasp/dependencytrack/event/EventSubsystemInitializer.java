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
package org.owasp.dependencytrack.event;

import alpine.event.LdapSyncEvent;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import alpine.tasks.LdapSyncTask;
import org.owasp.dependencytrack.tasks.DependencyCheckTask;
import org.owasp.dependencytrack.tasks.IndexTask;
import org.owasp.dependencytrack.tasks.MetricsUpdateTask;
import org.owasp.dependencytrack.tasks.NistMirrorTask;
import org.owasp.dependencytrack.tasks.NspMirrorTask;
import org.owasp.dependencytrack.tasks.ScanUploadProcessingTask;
import org.owasp.dependencytrack.tasks.TaskScheduler;
import org.owasp.dependencytrack.tasks.VulnDbSyncTask;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Initializes the event subsystem and configures event subscribers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class EventSubsystemInitializer implements ServletContextListener {

    // Starts the EventService
    private static final EventService EVENT_SERVICE = EventService.getInstance();

    // Starts the SingleThreadedEventService (Used for indexing service)
    private static final SingleThreadedEventService EVENT_SERVICE_INDEX = SingleThreadedEventService.getInstance();

    // Starts the SingleThreadedEventService (Used for Metrics updates)
    private static final SingleThreadedEventService EVENT_SERVICE_METRICS = SingleThreadedEventService.getInstance();

    // Starts the SingleThreadedEventService (Used for Dependency-Check analysis)
    private static final SingleThreadedEventService EVENT_SERVICE_ODC = SingleThreadedEventService.getInstance();

    /**
     * {@inheritDoc}
     */
    public void contextInitialized(ServletContextEvent event) {
        EVENT_SERVICE.subscribe(ScanUploadEvent.class, ScanUploadProcessingTask.class);
        EVENT_SERVICE.subscribe(LdapSyncEvent.class, LdapSyncTask.class);
        EVENT_SERVICE.subscribe(NistMirrorEvent.class, NistMirrorTask.class);
        EVENT_SERVICE.subscribe(NspMirrorEvent.class, NspMirrorTask.class);
        EVENT_SERVICE.subscribe(VulnDbSyncEvent.class, VulnDbSyncTask.class);

        EVENT_SERVICE_INDEX.subscribe(IndexEvent.class, IndexTask.class);
        EVENT_SERVICE_ODC.subscribe(DependencyCheckEvent.class, DependencyCheckTask.class);
        EVENT_SERVICE_METRICS.subscribe(MetricsUpdateEvent.class, MetricsUpdateTask.class);

        TaskScheduler.getInstance();
    }

    /**
     * {@inheritDoc}
     */
    public void contextDestroyed(ServletContextEvent event) {
        TaskScheduler.getInstance().shutdown();

        EVENT_SERVICE.unsubscribe(ScanUploadProcessingTask.class);
        EVENT_SERVICE.unsubscribe(LdapSyncTask.class);
        EVENT_SERVICE.unsubscribe(NistMirrorTask.class);
        EVENT_SERVICE.unsubscribe(NspMirrorTask.class);
        EVENT_SERVICE.unsubscribe(VulnDbSyncTask.class);
        EVENT_SERVICE.shutdown();

        EVENT_SERVICE_INDEX.unsubscribe(IndexTask.class);
        EVENT_SERVICE_INDEX.shutdown();

        EVENT_SERVICE_ODC.unsubscribe(DependencyCheckTask.class);
        EVENT_SERVICE_ODC.shutdown();

        EVENT_SERVICE_METRICS.unsubscribe(MetricsUpdateTask.class);
        EVENT_SERVICE_METRICS.shutdown();
    }
}
