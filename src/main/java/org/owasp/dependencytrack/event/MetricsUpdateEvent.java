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

import alpine.event.framework.Event;

/**
 * Defines an Event to update metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class MetricsUpdateEvent implements Event {

    private Object target = null;

    // Call this to perform a global metrics update event
    public MetricsUpdateEvent() {
    }

    // Call this to perform a metrics update on a specific project or component
    public MetricsUpdateEvent(Object target) {
        this.target = target;
    }

    public Object getTarget() {
        return target;
    }

}
