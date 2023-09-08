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
package org.dependencytrack.event;

import alpine.event.framework.SingletonCapableEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.search.IndexManager;

/**
 * Defines various Lucene index events.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexEvent extends SingletonCapableEvent {

    public enum Action {
        CREATE,
        UPDATE,
        DELETE,
        COMMIT,
        REINDEX,
        CHECK
    }

    private final Action action;
    private Object indexableObject;
    private Class indexableClass;

    public IndexEvent(final Action action, final Project project) {
        this(action, Project.class);
        this.indexableObject = project;
    }

    public IndexEvent(final Action action, final Component component) {
        this(action, Component.class);
        this.indexableObject = component;
    }

    public IndexEvent(final Action action, final ServiceComponent service) {
        this(action, ServiceComponent.class);
        this.indexableObject = service;
    }

    public IndexEvent(final Action action, final Vulnerability vulnerability) {
        this(action, Vulnerability.class);
        this.indexableObject = vulnerability;
    }

    public IndexEvent(final Action action, final License license) {
        this(action, License.class);
        this.indexableObject = license;
    }

    public IndexEvent(final Action action, final Cpe cpe) {
        this(action, Cpe.class);
        this.indexableObject = cpe;
    }

    public IndexEvent(final Action action, final VulnerableSoftware vs) {
        this(action, VulnerableSoftware.class);
        this.indexableObject = vs;
    }

    public IndexEvent(final Action action, final Class clazz) {
        if(action == Action.REINDEX) {
            this.setSingleton(true);
            this.setChainIdentifier(IndexManager.IndexType.getUuid(clazz));
        }
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
