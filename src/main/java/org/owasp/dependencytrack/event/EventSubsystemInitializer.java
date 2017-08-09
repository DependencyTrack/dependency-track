/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.event;

import alpine.event.LdapSyncEvent;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import alpine.tasks.LdapSyncTask;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencytrack.tasks.IndexTask;
import org.owasp.dependencytrack.tasks.NistMirrorTask;
import org.owasp.dependencytrack.tasks.NspMirrorTask;
import org.owasp.dependencytrack.tasks.ScanModeler;
import org.owasp.dependencytrack.tasks.MetricsUpdateTask;
import org.owasp.dependencytrack.tasks.TaskScheduler;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class EventSubsystemInitializer implements ServletContextListener {

    // Starts the EventService
    private static final EventService EVENT_SERVICE = EventService.getInstance();

    // Starts the SingleThreadedEventService
    private static final SingleThreadedEventService EVENT_SERVICE_ST = SingleThreadedEventService.getInstance();

    // Initialize Dependency-Check settings singleton before processing any event
    static {
        Settings.initialize();
    }

    public void contextInitialized(ServletContextEvent event) {
        EVENT_SERVICE.subscribe(MetricsUpdateEvent.class, MetricsUpdateTask.class);
        EVENT_SERVICE.subscribe(ScanUploadEvent.class, ScanModeler.class);
        EVENT_SERVICE.subscribe(LdapSyncEvent.class, LdapSyncTask.class);
        EVENT_SERVICE.subscribe(NistMirrorEvent.class, NistMirrorTask.class);
        EVENT_SERVICE.subscribe(NspMirrorEvent.class, NspMirrorTask.class);

        EVENT_SERVICE_ST.subscribe(IndexEvent.class, IndexTask.class);

        TaskScheduler.getInstance();
    }

    public void contextDestroyed(ServletContextEvent event) {
        TaskScheduler.getInstance().shutdown();

        EVENT_SERVICE.unsubscribe(MetricsUpdateTask.class);
        EVENT_SERVICE.unsubscribe(ScanModeler.class);
        EVENT_SERVICE.unsubscribe(LdapSyncTask.class);
        EVENT_SERVICE.unsubscribe(NistMirrorTask.class);
        EVENT_SERVICE.unsubscribe(NspMirrorTask.class);
        EVENT_SERVICE.shutdown();

        EVENT_SERVICE_ST.unsubscribe(IndexTask.class);
        EVENT_SERVICE_ST.shutdown();
    }
}
