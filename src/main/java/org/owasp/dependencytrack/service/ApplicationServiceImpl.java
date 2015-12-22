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

import org.owasp.dependencytrack.dao.ApplicationDao;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
public class ApplicationServiceImpl implements ApplicationService {

    @Autowired
    private ApplicationDao applicationDao;

    @Override
    @Transactional
    public List<Application> listApplications() {
        return applicationDao.listApplications();
    }

    @Override
    @Transactional
    public void addApplication(Application application, String version) {
        applicationDao.addApplication(application, version);
    }

    @Override
    @Transactional
    public void updateApplication(int id, String name) {
        applicationDao.updateApplication(id, name);
    }

    @Override
    @Transactional
    public void deleteApplication(int id) {
        applicationDao.deleteApplication(id);
    }


    @Override
    @Transactional
    public Set<Application> searchApplications(int libverid) {
        return applicationDao.searchApplications(libverid);
    }

    @Override
    @Transactional
    public Set<Application> searchAllApplications(int libid) {
        return applicationDao.searchAllApplications(libid);
    }

    @Override
    @Transactional
    public List<ApplicationVersion> searchApplicationsVersion(int libverid) {
        return applicationDao.searchApplicationsVersion(libverid);
    }

    @Override
    @Transactional
    public List<ApplicationVersion> searchAllApplicationsVersions(int libid) {
        return applicationDao.searchAllApplicationsVersions(libid);
    }

    @Override
    @Transactional
    public Set<Application> coarseSearchApplications(int libid) {
        return applicationDao.coarseSearchApplications(libid);
    }

    @Override
    @Transactional
    public List<ApplicationVersion> coarseSearchApplicationVersions(int libid) {
        return applicationDao.coarseSearchApplicationVersions(libid);
    }

}
