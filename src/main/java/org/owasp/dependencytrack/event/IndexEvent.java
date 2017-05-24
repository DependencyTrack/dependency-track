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
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Vulnerability;

public abstract class IndexEvent implements Event {

    private Object indexableObject;
    private Class indexableClass;

    public IndexEvent() { }

    public IndexEvent(Project project) {
        this.indexableObject = project;
    }

    public IndexEvent(Component component) {
        this.indexableObject = component;
    }

    public IndexEvent(Vulnerability vulnerability) {
        this.indexableObject = vulnerability;
    }

    public IndexEvent(License license) {
        this.indexableObject = license;
    }

    public IndexEvent(Class clazz) {
        this.indexableClass = clazz;
    }

    public Object getObject() {
        return indexableObject;
    }

    public Class getIndexableClass() {
        return indexableClass;
    }
}
