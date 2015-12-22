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
package org.owasp.dependencytrack.tasks.dependencycheck;

import org.owasp.dependencycheck.dependency.Dependency;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Java Bean class for dependencies found by DependencyCheck.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class Analysis {

    /**
     * All dependencies as the result of an analysis.
     */
    private final List<Dependency> dependencies = new ArrayList<>();

    /**
     * Adds a new dependency to this collection.
     *
     * @param dependency the dependency to add
     */
    public void addDependency(final Dependency dependency) {
        dependencies.add(dependency);
    }

    /**
     * Returns a read-only collection of all dependencies from the analysis.
     *
     * @return all dependencies from the analysis
     */
    public Collection<Dependency> getDependencies() {
        return Collections.unmodifiableCollection(dependencies);
    }
}
