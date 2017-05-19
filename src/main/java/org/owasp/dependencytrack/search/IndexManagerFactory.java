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
package org.owasp.dependencytrack.search;

import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Vulnerability;

public class IndexManagerFactory {

    public static ObjectIndexer getIndexManager(IndexEvent event) {
        if (event.getObject() instanceof Project) {
            return new ProjectIndexer();
        } else if (event.getObject() instanceof Component) {
            return new ComponentIndexer();
        } else if (event.getObject() instanceof Vulnerability) {
            return new VulnerabilityIndexer();
        } else if (event.getObject() instanceof License) {
            return new LicenseIndexer();
        }
        throw new IllegalArgumentException("Unsupported indexer requested");
    }

}
