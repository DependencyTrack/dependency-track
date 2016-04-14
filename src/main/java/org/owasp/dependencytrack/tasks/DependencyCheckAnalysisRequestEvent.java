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
package org.owasp.dependencytrack.tasks;

import org.owasp.dependencytrack.model.LibraryVersion;
import org.springframework.context.ApplicationEvent;

import java.util.List;

/**
 * An event object for performing a Dependency-Check analysis.
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class DependencyCheckAnalysisRequestEvent extends ApplicationEvent {

    /**
	 * 
	 */
	private static final long serialVersionUID = -2670998415277531364L;
	/**
     * A list of library versions to scan.
     */
    private List<LibraryVersion> libraryVersions;

    /**
     * Constructs a new DependencyCheckAnalysisRequestEvent.
     * @param source the source object making the call
     * @param libraryVersions a list of library versions to scan
     */
    public DependencyCheckAnalysisRequestEvent(Object source, List<LibraryVersion> libraryVersions) {
        super(source);
        this.libraryVersions = libraryVersions;
    }

    /**
     * Constructs a new DependencyCheckAnalysisRequestEvent.
     * @param source the source object making the call
     */
    public DependencyCheckAnalysisRequestEvent(Object source) {
        super(source);
    }

    /**
     * Returns a list of library versions that should be scanned.
     * @return a list of library versions
     */
    public List<LibraryVersion> getLibraryVersions() {
        return libraryVersions;
    }

}
