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

package org.owasp.dependencytrack.dao;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.json.JSONObject;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationDependency;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.ScanResult;
import org.owasp.dependencytrack.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ApplicationVersionDao {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationVersionDao.class);

    /**
     * The Hibernate SessionFactory
     */
    @Autowired
    private SessionFactory sessionFactory;

    /**
     * Returns an ApplicationVersion with the specified ID.
     *
     * @param id The ID of the ApplicationVersion to return
     * @return An ApplicationVersion object
     */
    @SuppressWarnings("unchecked")
    public ApplicationVersion getApplicationVersion(int id) {
        final Query query = sessionFactory.getCurrentSession().createQuery("from ApplicationVersion where id=:id");
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
    public void deleteApplicationVersion(Integer id) {
        /*Session session = sessionFactory.openSession();
        session.beginTransaction();*/
        final ApplicationVersion applicationVersion = (ApplicationVersion) sessionFactory
                .getCurrentSession().load(ApplicationVersion.class, id);
        final Query query = sessionFactory.getCurrentSession().
                createQuery("from ApplicationDependency where applicationVersion=:appver");
        query.setParameter("appver", applicationVersion);

        if (!query.list().isEmpty()) {
            final List<ApplicationDependency> applicationDependencies = query.list();
            for (ApplicationDependency appdep : applicationDependencies) {
                sessionFactory.getCurrentSession().delete(appdep);
            }
        }

        if (null != applicationVersion) {
            sessionFactory.getCurrentSession().delete(applicationVersion);
        }
    }

    /**
     * Adds an ApplicationVersion to the specified Application with the specified version string.
     *
     * @param appid      The Application to add a version to
     * @param appversion The string representation of the version
     */
    public void addApplicationVersion(int appid, String appversion) {
        final Session session = sessionFactory.openSession();
        final Application application = (Application) session.load(Application.class, appid);
        if (null != application) {
            session.beginTransaction();
            final ApplicationVersion version = new ApplicationVersion();
            version.setVersion(appversion);
            version.setApplication(application);
            session.save(version);
            session.getTransaction().commit();
        }
        session.close();
    }

    /**
     * Clone the specified Application (by ID) and give it a new name.
     *
     * @param applicationid   The ID of the Application object to clone
     * @param applicationname The new name of the cloned Application
     */
    @SuppressWarnings("unchecked")
    public void cloneApplication(int applicationid, String applicationname) {
        Query query = sessionFactory.getCurrentSession().createQuery("from Application where id=:id");
        query.setParameter("id", applicationid);

        final Application findapplication = (Application) query.list().get(0);

        query = sessionFactory.getCurrentSession().
                createQuery("from ApplicationVersion AS appver where appver.application=:findapplication");
        query.setParameter("findapplication", findapplication);

        final List<ApplicationVersion> applicationVersions = query.list();

        final Session session = sessionFactory.openSession();
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
        session.close();
    }

    /**
     * Clones the specified Application.
     *
     * @param applicationid The ID of the Application to clone
     * @param newversion    The new version string of the cloned ApplicationVersion
     * @param curappver     The current version string of the ApplicationVersion to clone
     */
    @SuppressWarnings("unchecked")
    public void cloneApplicationVersion(int applicationid, String newversion, String curappver) {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        Query query = session.createQuery("from Application AS apps where apps.id=:findapplication");
        query.setParameter("findapplication", applicationid);

        final Application app = (Application) query.list().get(0);

        query = session.createQuery("from ApplicationVersion AS appver where "
                + "appver.application=:findapplication and appver.version=:curappver");

        query.setParameter("findapplication", app);
        query.setParameter("curappver", curappver);

        final ApplicationVersion applicationVersion = (ApplicationVersion) query.list().get(0);
        final ApplicationVersion newApplicationVersion = (ApplicationVersion) applicationVersion.clone();
        newApplicationVersion.setVersion(newversion);
        session.save(newApplicationVersion);

        query = session.createQuery("from ApplicationDependency AS appdep "
                + "where appdep.applicationVersion=:findappverr");
        query.setParameter("findappverr", applicationVersion);

        final List<ApplicationDependency> applicationDependencies = query.list();

        for (ApplicationDependency appdep : applicationDependencies) {
            final ApplicationDependency newDependencies = (ApplicationDependency) appdep.clone();
            newDependencies.setApplicationVersion(newApplicationVersion);
            session.save(newDependencies);
        }

        session.getTransaction().commit();
        session.close();
    }

    /**
     * Updates the specified ApplicationVersion with a new string representation of the version.
     *
     * @param id         The ID of the ApplicationVersion to update
     * @param appversion The new version label to use
     */
    public void updateApplicationVersion(int id, String appversion) {
        final Query query = sessionFactory.getCurrentSession().createQuery(
                "update ApplicationVersion set version=:ver " + "where id=:appverid");

        query.setParameter("ver", appversion);
        query.setParameter("appverid", id);
        query.executeUpdate();
    }

}
