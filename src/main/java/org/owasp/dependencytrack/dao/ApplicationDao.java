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
package org.owasp.dependencytrack.dao;

import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;

import java.util.List;
import java.util.Set;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface ApplicationDao extends IBaseDao {

    @SuppressWarnings("unchecked")
    List<Application> listApplications();

    void addApplication(Application application, String version);

    void updateApplication(int id, String name);

    @SuppressWarnings("unchecked")
    void deleteApplication(int id);

    @SuppressWarnings("unchecked")
    Set<Application> searchApplications(int libverid);

    @SuppressWarnings("unchecked")
    List<ApplicationVersion> searchApplicationsVersion(int libverid);

    @SuppressWarnings("unchecked")
    Set<Application> searchAllApplications(int libid);

    @SuppressWarnings("unchecked")
    List<ApplicationVersion> searchAllApplicationsVersions(int libid);

    @SuppressWarnings("unchecked")
    Set<Application> coarseSearchApplications(int vendorID);

    @SuppressWarnings("unchecked")
    List<ApplicationVersion> coarseSearchApplicationVersions(int vendorID);
}
