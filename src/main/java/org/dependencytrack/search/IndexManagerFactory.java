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
package org.dependencytrack.search;

import alpine.Config;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.search.document.ComponentDocument;
import org.dependencytrack.search.document.DummyDocument;
import org.dependencytrack.search.document.LicenseDocument;
import org.dependencytrack.search.document.ProjectDocument;
import org.dependencytrack.search.document.SearchDocument;
import org.dependencytrack.search.document.ServiceComponentDocument;
import org.dependencytrack.search.document.VulnerabilityDocument;
import org.dependencytrack.search.document.VulnerableSoftwareDocument;

/**
 * Creates IndexManager implementations based on event types.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexManagerFactory {

    public static ObjectIndexer<? extends SearchDocument> getIndexManager(final IndexEvent event) {
        if (Config.isUnitTestsEnabled()) {
            return new ObjectIndexer<DummyDocument>() {
                @Override
                public String[] getSearchFields() { return new String[0]; }
                @Override
                public void add(final DummyDocument object) { }
                @Override
                public void update(final DummyDocument object) { }
                @Override
                public void remove(final DummyDocument object) { }
                @Override
                public void commit() { }
                @Override
                public void reindex() { }
            };
        }
        if (event.getDocument() instanceof ProjectDocument || Project.class == event.getIndexableClass()) {
            return ProjectIndexer.getInstance();
        } else if (event.getDocument() instanceof ComponentDocument || Component.class == event.getIndexableClass()) {
            return ComponentIndexer.getInstance();
        } else if (event.getDocument() instanceof ServiceComponentDocument || ServiceComponent.class == event.getIndexableClass()) {
            return ServiceComponentIndexer.getInstance();
        } else if (event.getDocument() instanceof VulnerabilityDocument || Vulnerability.class == event.getIndexableClass()) {
            return VulnerabilityIndexer.getInstance();
        } else if (event.getDocument() instanceof LicenseDocument || License.class == event.getIndexableClass()) {
            return LicenseIndexer.getInstance();
        } else if (event.getDocument() instanceof VulnerableSoftwareDocument || VulnerableSoftware.class == event.getIndexableClass()) {
            return VulnerableSoftwareIndexer.getInstance();
        }
        throw new IllegalArgumentException("Unsupported indexer requested");
    }

    public static IndexManager getIndexManager(final Class<?> clazz) {
        if (Project.class == clazz) {
            return ProjectIndexer.getInstance();
        } else if (Component.class == clazz) {
            return ComponentIndexer.getInstance();
        } else if (ServiceComponent.class == clazz) {
            return ServiceComponentIndexer.getInstance();
        } else if (Vulnerability.class == clazz) {
            return VulnerabilityIndexer.getInstance();
        } else if (License.class == clazz) {
            return LicenseIndexer.getInstance();
        } else if (VulnerableSoftware.class == clazz) {
            return VulnerableSoftwareIndexer.getInstance();
        }
        throw new IllegalArgumentException("Unsupported indexer requested");
    }

}
