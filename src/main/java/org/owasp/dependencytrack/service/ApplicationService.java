/*
 * Copyright 2013 OWASP Foundation
 *
 * This file is part of OWASP Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Dependency-Track.
 * If not, see http://www.gnu.org/licenses/.
 */

package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.dao.ApplicationDao;
import org.owasp.dependencytrack.model.Application;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ApplicationService {

    @Autowired
    private ApplicationDao applicationDao;

    @Transactional
    public List<Application> listApplications() {
        return applicationDao.listApplications();
    }

    @Transactional
    public void addApplication(Application application, String version) {
        applicationDao.addApplication(application, version);
    }

    @Transactional
    public void updateApplication(int id, String name) {
        applicationDao.updateApplication(id, name);
    }

    @Transactional
    public void deleteApplication(int id) {
        applicationDao.deleteApplication(id);
    }

}