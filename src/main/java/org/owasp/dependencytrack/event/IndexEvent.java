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

/**
 * Defines various Lucene index events.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexEvent implements Event {

    public enum Action {
        CREATE,
        UPDATE,
        DELETE,
        COMMIT,
        REINDEX
    }

    private Action action;
    private Object indexableObject;
    private Class indexableClass;


    public IndexEvent(Action action, Project project) {
        this.action = action;
        this.indexableObject = project;
    }

    public IndexEvent(Action action, Component component) {
        this.action = action;
        this.indexableObject = component;
    }

    public IndexEvent(Action action, Vulnerability vulnerability) {
        this.action = action;
        this.indexableObject = vulnerability;
    }

    public IndexEvent(Action action, License license) {
        this.action = action;
        this.indexableObject = license;
    }

    public IndexEvent(Action action, Class clazz) {
        this.action = action;
        this.indexableClass = clazz;
    }

    public Action getAction() {
        return action;
    }

    public Object getObject() {
        return indexableObject;
    }

    public Class getIndexableClass() {
        return indexableClass;
    }
}
