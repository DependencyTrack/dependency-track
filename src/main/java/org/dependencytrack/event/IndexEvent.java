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
package org.dependencytrack.event;

import alpine.event.framework.AbstractChainableEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.search.document.ComponentDocument;
import org.dependencytrack.search.document.LicenseDocument;
import org.dependencytrack.search.document.ProjectDocument;
import org.dependencytrack.search.document.SearchDocument;
import org.dependencytrack.search.document.ServiceComponentDocument;
import org.dependencytrack.search.document.VulnerabilityDocument;
import org.dependencytrack.search.document.VulnerableSoftwareDocument;

/**
 * Defines various Lucene index events.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexEvent extends AbstractChainableEvent {

    public enum Action {
        CREATE,
        UPDATE,
        DELETE,
        COMMIT,
        REINDEX,
        CHECK
    }

    private final Action action;
    private SearchDocument searchDocument;
    private final Class<?> indexableClass;

    public IndexEvent(final Action action, final Project project) {
        this(action, Project.class);
        this.searchDocument = new ProjectDocument(project);
    }

    public IndexEvent(final Action action, final Component component) {
        this(action, Component.class);
        this.searchDocument = new ComponentDocument(component);
    }

    public IndexEvent(final Action action, final ServiceComponent service) {
        this(action, ServiceComponent.class);
        this.searchDocument = new ServiceComponentDocument(service);
    }

    public IndexEvent(final Action action, final Vulnerability vulnerability) {
        this(action, Vulnerability.class);
        this.searchDocument = new VulnerabilityDocument(vulnerability);
    }

    public IndexEvent(final Action action, final License license) {
        this(action, License.class);
        this.searchDocument = new LicenseDocument(license);
    }

    public IndexEvent(final Action action, final VulnerableSoftware vs) {
        this(action, VulnerableSoftware.class);
        this.searchDocument = new VulnerableSoftwareDocument(vs);
    }

    public IndexEvent(final Action action, final Class<?> clazz) {
        this.action = action;
        this.indexableClass = clazz;
    }

    public Action getAction() {
        return action;
    }

    public SearchDocument getDocument() {
        return searchDocument;
    }

    public Class<?> getIndexableClass() {
        return indexableClass;
    }
}
