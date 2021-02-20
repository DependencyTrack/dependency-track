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
package org.dependencytrack.search;

import alpine.Config;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;

/**
 * Creates IndexManager implementations based on event types.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexManagerFactory {

    public static ObjectIndexer getIndexManager(final IndexEvent event) {
        if (Config.isUnitTestsEnabled()) {
            return new ObjectIndexer() {
                @Override
                public String[] getSearchFields() { return new String[0]; }
                @Override
                public void add(final Object object) { }
                @Override
                public void remove(final Object object) { }
                @Override
                public void commit() { }
                @Override
                public void reindex() { }
            };
        }
        if (event.getObject() instanceof Project || Project.class == event.getIndexableClass()) {
            return ProjectIndexer.getInstance();
        } else if (event.getObject() instanceof Component || Component.class == event.getIndexableClass()) {
            return ComponentIndexer.getInstance();
        } else if (event.getObject() instanceof ServiceComponent || ServiceComponent.class == event.getIndexableClass()) {
            return ServiceComponentIndexer.getInstance();
        } else if (event.getObject() instanceof Vulnerability || Vulnerability.class == event.getIndexableClass()) {
            return VulnerabilityIndexer.getInstance();
        } else if (event.getObject() instanceof License || License.class == event.getIndexableClass()) {
            return LicenseIndexer.getInstance();
        } else if (event.getObject() instanceof Cpe || Cpe.class == event.getIndexableClass()) {
            return CpeIndexer.getInstance();
        } else if (event.getObject() instanceof VulnerableSoftware || VulnerableSoftware.class == event.getIndexableClass()) {
            return VulnerableSoftwareIndexer.getInstance();
        }
        throw new IllegalArgumentException("Unsupported indexer requested");
    }

}
