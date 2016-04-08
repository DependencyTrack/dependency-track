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

import org.hibernate.Query;
import org.hibernate.Session;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationDependency;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ApplicationVersionDaoImpl extends BaseDao implements ApplicationVersionDao {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationVersionDaoImpl.class);

    /**
     * Returns an ApplicationVersion with the specified ID.
     *
     * @param id The ID of the ApplicationVersion to return
     * @return An ApplicationVersion object
     */
    @SuppressWarnings("unchecked")
    public ApplicationVersion getApplicationVersion(final int id) {
        final Session session = getSession();
        final Query query = session.createQuery("from ApplicationVersion where id=:id");
        query.setParameter("id", id);

        final List<ApplicationVersion> result = query.list();
        if (result.size() > 0) {
            return result.get(0);
        }
        return new ApplicationVersion();
    }

    /**
     * Deletes an ApplicationVersion with the specified ID.
     *
     * @param id The ID of the ApplicationVersion to delete
     */
    @SuppressWarnings("unchecked")
    public void deleteApplicationVersion(final Integer id) {
        final Session session = getSession();
        session.beginTransaction();
        final ApplicationVersion applicationVersion = (ApplicationVersion) session.load(ApplicationVersion.class, id);
        final Query query = session.createQuery("from ApplicationDependency where applicationVersion=:appver");
        query.setParameter("appver", applicationVersion);

        if (!query.list().isEmpty()) {
            final List<ApplicationDependency> applicationDependencies = query.list();
            for (ApplicationDependency appdep : applicationDependencies) {
                session.delete(appdep);
            }
        }

        if (null != applicationVersion) {
            session.delete(applicationVersion);
        }
        session.getTransaction().commit();
    }

    /**
     * Adds an ApplicationVersion to the specified Application with the specified version string.
     *
     * @param appid      The Application to add a version to
     * @param appversion The string representation of the version
     */
    public void addApplicationVersion(final int appid, final String appversion) {
        final Session session = getSession();
        session.getTransaction().begin();
        final Application application = (Application) session.load(Application.class, appid);
        if (null != application) {
            final ApplicationVersion version = new ApplicationVersion();
            version.setVersion(appversion);
            version.setApplication(application);
            session.save(version);
        }
        session.getTransaction().commit();
    }

    /**
     * Clone the specified Application (by ID) and give it a new name.
     *
     * @param applicationid   The ID of the Application object to clone
     * @param applicationname The new name of the cloned Application
     */
    @SuppressWarnings("unchecked")
    public void cloneApplication(final int applicationid, final String applicationname) {
        final Session session = getSession();
        Query query = session.createQuery("from Application where id=:id");
        query.setParameter("id", applicationid);

        final Application findapplication = (Application) query.list().get(0);

        query = session.createQuery("from ApplicationVersion AS appver where appver.application=:findapplication");
        query.setParameter("findapplication", findapplication);

        final List<ApplicationVersion> applicationVersions = query.list();

        session.beginTransaction();
        final Application application = new Application();
        application.setName(applicationname);
        session.save(application);

        for (ApplicationVersion appver : applicationVersions) {

            final ApplicationVersion newApplicationVersion = (ApplicationVersion) appver.clone();
            newApplicationVersion.setApplication(application);
            session.save(newApplicationVersion);

            query = session.createQuery("from ApplicationDependency AS appdep where appdep.applicationVersion.id=:id");
            query.setParameter("id", appver.getId());
            if (!query.list().isEmpty()) {
                final List<ApplicationDependency> applicationDependencies = query.list();
                for (ApplicationDependency appdep : applicationDependencies) {
                    final ApplicationDependency newDependencies = (ApplicationDependency) appdep.clone();
                    newDependencies.setApplicationVersion(newApplicationVersion);
                    session.save(newDependencies);
                }
            }
        }
        session.getTransaction().commit();
    }

    /**
     * Clones the specified Application.
     *
     * @param applicationid The ID of the Application to clone
     * @param newversion    The new version string of the cloned ApplicationVersion
     * @param curappver     The current version string of the ApplicationVersion to clone
     */
    @SuppressWarnings("unchecked")
    public void cloneApplicationVersion(final int applicationid, final String newversion, final String curappver) {
        final Session session = getSession();
        session.beginTransaction();

        Query query = session.createQuery("from Application AS apps where apps.id=:findapplication");
        query.setParameter("findapplication", applicationid);

        final Application app = (Application) query.list().get(0);

        query = session.createQuery("from ApplicationVersion AS appver where appver.application=:findapplication and appver.version=:curappver");

        query.setParameter("findapplication", app);
        query.setParameter("curappver", curappver);

        final ApplicationVersion applicationVersion = (ApplicationVersion) query.list().get(0);
        final ApplicationVersion newApplicationVersion = (ApplicationVersion) applicationVersion.clone();
        newApplicationVersion.setVersion(newversion);
        session.save(newApplicationVersion);

        query = session.createQuery("from ApplicationDependency AS appdep where appdep.applicationVersion=:findappverr");
        query.setParameter("findappverr", applicationVersion);

        final List<ApplicationDependency> applicationDependencies = query.list();

        for (ApplicationDependency appdep : applicationDependencies) {
            final ApplicationDependency newDependencies = (ApplicationDependency) appdep.clone();
            newDependencies.setApplicationVersion(newApplicationVersion);
            session.save(newDependencies);
        }
        session.getTransaction().commit();
    }

    /**
     * Updates the specified ApplicationVersion with a new string representation of the version.
     *
     * @param id         The ID of the ApplicationVersion to update
     * @param appversion The new version label to use
     */
    public void updateApplicationVersion(final int id, final String appversion) {
        final Session session = getSession();
        final Query query = session.createQuery("update ApplicationVersion set version=:ver where id=:appverid");
        query.setParameter("ver", appversion);
        query.setParameter("appverid", id);
        query.executeUpdate();
    }

}
