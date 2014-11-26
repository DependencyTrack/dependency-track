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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.tasks;

import org.owasp.dependencytrack.model.LibraryVersion;
import org.springframework.context.ApplicationEvent;

import java.util.List;

public class DependencyCheckAnalysisRequestEvent extends ApplicationEvent {

    private List<LibraryVersion> libraryVersions;

    public DependencyCheckAnalysisRequestEvent(List<LibraryVersion> libraryVersions) {
        super(libraryVersions);
        this.libraryVersions = libraryVersions;
    }

    public List<LibraryVersion> getLibraryVersions() {
        return libraryVersions;
    }

}
