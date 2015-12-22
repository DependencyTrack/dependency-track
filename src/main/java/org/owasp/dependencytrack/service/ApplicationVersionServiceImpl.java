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

import org.owasp.dependencytrack.dao.ApplicationVersionDao;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ApplicationVersionServiceImpl implements ApplicationVersionService {

    @Autowired
    private ApplicationVersionDao applicationVersionDao;

    @Override
    @Transactional
    public ApplicationVersion getApplicationVersion(int id) {
        return applicationVersionDao.getApplicationVersion(id);
    }

    @Override
    @Transactional
    public void deleteApplicationVersion(Integer id) {
        applicationVersionDao.deleteApplicationVersion(id);
    }

    @Override
    @Transactional
    public void addApplicationVersion(int appid, String appversion) {
        applicationVersionDao.addApplicationVersion(appid, appversion);
    }

    @Override
    @Transactional
    public void cloneApplication(Integer applicationid, String applicationname) {
        applicationVersionDao.cloneApplication(applicationid, applicationname);
    }

    @Override
    @Transactional
    public void cloneApplicationVersion(Integer applicationid, String newversion, String applicationversion) {
        applicationVersionDao.cloneApplicationVersion(applicationid, newversion, applicationversion);
    }

    @Override
    @Transactional
    public void updateApplicationVersion(int id, String appversion) {
        applicationVersionDao.updateApplicationVersion(id, appversion);

    }

}
