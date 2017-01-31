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
package org.owasp.dependencytrack.tasks;

import org.owasp.dependencytrack.event.LdapSyncEvent;
import org.owasp.dependencytrack.event.NistMirrorEvent;
import org.owasp.dependencytrack.event.framework.Event;
import org.owasp.dependencytrack.event.framework.EventService;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class TaskScheduler {

    // Holds an instance of TaskScheduler
    private static final TaskScheduler instance = new TaskScheduler();

    // Holds a list of all timers created during construction
    private List<Timer> timers = new ArrayList<>();

    private TaskScheduler() {

        // Creates a new event that executes every 6 hours (21600000) after an initial 10 second (10000) delay
        scheduleEvent(new LdapSyncEvent(), 10000, 21600000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 1 minute (60000) delay
        scheduleEvent(new NistMirrorEvent(), 60000, 86400000);
    }

    /**
     * Return an instance of the TaskScheduler instance
     * @return a TaskScheduler instance
     */
    public static TaskScheduler getInstance() {
        return instance;
    }

    private void scheduleEvent(Event event, long delay, long period) {
        Timer timer = new Timer();
        timer.schedule(new ScheduleEvent().event(event), delay, period);
        timers.add(timer);
    }

    private class ScheduleEvent extends TimerTask {
        private Event event;

        public ScheduleEvent event(Event event) {
            this.event = event;
            return this;
        }

        public synchronized void run() {
            EventService.getInstance().publish(event);
        }
    }

    public void shutdown() {
        for (Timer timer: timers) {
            timer.cancel();
        }
    }

}