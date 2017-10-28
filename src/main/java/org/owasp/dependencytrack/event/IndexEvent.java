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
