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
package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.model.ApplicationVersion;
import org.springframework.transaction.annotation.Transactional;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface ApplicationVersionService {
    @Transactional
    ApplicationVersion getApplicationVersion(int id);

    @Transactional
    void deleteApplicationVersion(Integer id);

    @Transactional
    void addApplicationVersion(int appid, String appversion);

    @Transactional
    void cloneApplication(Integer applicationid, String applicationname);

    @Transactional
    void cloneApplicationVersion(Integer applicationid, String newversion, String applicationversion);

    @Transactional
    void updateApplicationVersion(int id, String appversion);
}
