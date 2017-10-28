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
package org.owasp.dependencytrack.search;

import alpine.Config;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Vulnerability;

/**
 * Creates IndexManager implementations based on event types.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexManagerFactory {

    public static ObjectIndexer getIndexManager(IndexEvent event) {
        if (Config.isUnitTestsEnabled()) {
            return new ObjectIndexer() {
                @Override
                public String[] getSearchFields() { return new String[0]; }
                @Override
                public void add(Object object) { }
                @Override
                public void remove(Object object) { }
                @Override
                public void commit() { }
            };
        }
        if (event.getObject() instanceof Project || Project.class == event.getIndexableClass()) {
            return ProjectIndexer.getInstance();
        } else if (event.getObject() instanceof Component || Component.class == event.getIndexableClass()) {
            return ComponentIndexer.getInstance();
        } else if (event.getObject() instanceof Vulnerability || Vulnerability.class == event.getIndexableClass()) {
            return VulnerabilityIndexer.getInstance();
        } else if (event.getObject() instanceof License || License.class == event.getIndexableClass()) {
            return LicenseIndexer.getInstance();
        }
        throw new IllegalArgumentException("Unsupported indexer requested");
    }

}
