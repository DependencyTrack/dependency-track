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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.persistence.listener;

import alpine.event.framework.Event;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;

import javax.jdo.JDOHelper;
import javax.jdo.listener.DeleteLifecycleListener;
import javax.jdo.listener.InstanceLifecycleEvent;
import javax.jdo.listener.InstanceLifecycleListener;
import javax.jdo.listener.StoreLifecycleListener;
import java.util.function.Consumer;

/**
 * A {@link InstanceLifecycleListener} that emits {@link IndexEvent}s upon creation, modification, or deletion of instances.
 *
 * @since 4.11.0
 */
public class IndexingInstanceLifecycleListener implements DeleteLifecycleListener, StoreLifecycleListener {

    private final Consumer<Event> eventConsumer;

    public IndexingInstanceLifecycleListener(final Consumer<Event> eventConsumer) {
        this.eventConsumer = eventConsumer;
    }

    @Override
    public void preDelete(final InstanceLifecycleEvent event) {
        final Object instance = event.getPersistentInstance();

        if (JDOHelper.isDeleted(instance)) {
            // preDelete is called twice:
            // - once when deletePersistent(All) is called
            // - once when flushing
            // Ignore the second call to avoid duplicate IndexEvents
            return;
        }

        if (instance instanceof final Component component) {
            eventConsumer.accept(new IndexEvent(IndexEvent.Action.DELETE, component));
        } else if (instance instanceof final Project project) {
            eventConsumer.accept(new IndexEvent(IndexEvent.Action.DELETE, project));
        } else if (instance instanceof final ServiceComponent service) {
            eventConsumer.accept(new IndexEvent(IndexEvent.Action.DELETE, service));
        } else if (instance instanceof final Vulnerability vuln) {
            eventConsumer.accept(new IndexEvent(IndexEvent.Action.DELETE, vuln));
        } else if (instance instanceof final VulnerableSoftware vs) {
            eventConsumer.accept(new IndexEvent(IndexEvent.Action.DELETE, vs));
        }
    }

    @Override
    public void postDelete(final InstanceLifecycleEvent event) {
    }

    @Override
    public void preStore(final InstanceLifecycleEvent event) {
        final Object instance = event.getPersistentInstance();

        final IndexEvent.Action action;
        if (JDOHelper.isNew(instance)) {
            action = IndexEvent.Action.CREATE;
        } else if (JDOHelper.isDirty(instance)) {
            action = IndexEvent.Action.UPDATE;
        } else {
            return;
        }

        if (instance instanceof final Component component) {
            eventConsumer.accept(new IndexEvent(action, component));
        } else if (instance instanceof final Project project) {
            eventConsumer.accept(new IndexEvent(action, project));
        } else if (instance instanceof final ProjectMetadata projectMetadata) {
            eventConsumer.accept(new IndexEvent(action, projectMetadata.getProject()));
        } else if (instance instanceof final ServiceComponent service) {
            eventConsumer.accept(new IndexEvent(action, service));
        } else if (instance instanceof final Vulnerability vuln) {
            eventConsumer.accept(new IndexEvent(action, vuln));
        } else if (instance instanceof final VulnerableSoftware vs) {
            eventConsumer.accept(new IndexEvent(action, vs));
        }
    }

    @Override
    public void postStore(final InstanceLifecycleEvent event) {
    }


}
