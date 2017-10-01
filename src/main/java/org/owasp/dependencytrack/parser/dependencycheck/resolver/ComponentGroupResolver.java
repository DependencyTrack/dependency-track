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
package org.owasp.dependencytrack.parser.dependencycheck.resolver;

import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;

/**
 * Attempts to resolve the group of the component from evidence
 * available in the specified dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ComponentGroupResolver extends AbstractStringResolver implements IResolver {

    /**
     * {@inheritDoc}
     */
    public String resolve(Dependency dependency) {
        return resolve(dependency, "vendor", 3);
    }

}
