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

package org.owasp.dependencytrack.dao;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.owasp.dependencytrack.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ApplicationVersionDao {

    @Autowired
    private SessionFactory sessionFactory;

    @SuppressWarnings("unchecked")
    public List<ApplicationVersion> listApplicationVersions() {

        Query query = sessionFactory.getCurrentSession().createQuery(
                "FROM ApplicationVersion");

        return query.list();
    }

    /*
        Returns an application version with the specified id
     */
    @SuppressWarnings("unchecked")
    public ApplicationVersion getApplicationVersion(int id) {
        Query query = sessionFactory.getCurrentSession().createQuery("from ApplicationVersion where id=:id");
        query.setParameter("id", id);

        List<ApplicationVersion> result = query.list();
        if (result.size() > 0) {
            return result.get(0);
        }
        return new ApplicationVersion();
    }

    public void removeApplicationVersion(Integer id) {
        ApplicationVersion applicationVersion = (ApplicationVersion) sessionFactory
                .getCurrentSession().load(ApplicationVersion.class, id);
        if (null != applicationVersion) {
            sessionFactory.getCurrentSession().delete(applicationVersion);
        }
    }

    public void updateApplication(int appversionid, int appid, String appname, String appversion) {

        Query query = sessionFactory.getCurrentSession().createQuery(
                "update Application set appname=:name " + "where id=:prodverid");

        query.setParameter("name", appname);
        query.setParameter("appverid", appid);
        int result = query.executeUpdate();

        Application application = new Application();
        application.setId(appid);
        application.setName(appname);

        query = sessionFactory.getCurrentSession().createQuery(
                "update ApplicationVersion set version=:ver," + "application=:app " + "where id=:appverid");

        query.setParameter("ver", appversion);
        query.setParameter("app", application);
        query.setParameter("appverid", appversionid);
        result = query.executeUpdate();
    }

    public void addApplicationVersion(int appid, String appversion) {
        Session session = sessionFactory.openSession();
        Application application = (Application) session.load(Application.class, appid);
        if (null != application) {
            session.beginTransaction();
            ApplicationVersion version = new ApplicationVersion();
            version.setVersion(appversion);
            version.setApplication(application);
            session.save(version);
            session.getTransaction().commit();
        }
        session.close();
    }

    public void cloneApplication(Integer appversionid) {
        Query query = sessionFactory.getCurrentSession().createQuery("from ApplicationDependency AS appdep where appdep.appVersion.id=:id");
        query.setParameter("id", appversionid);

        ApplicationDependency pDep = (ApplicationDependency) query.list().get(0);
        List<ApplicationDependency> lDep = query.list();

        Session session = sessionFactory.openSession();
        session.beginTransaction();

        Application application = pDep.getApplicationVersion().getApplication();
        Application newApplication = (Application) application.clone();
        session.save(newApplication);

        ApplicationVersion applicationVersion = pDep.getApplicationVersion();
        applicationVersion.setApplication(newApplication);
        ApplicationVersion newApplicationVersion = (ApplicationVersion) applicationVersion.clone();
        session.save(newApplicationVersion);

        for (ApplicationDependency dependencies : lDep) {
            LibraryVendor libraryVendor = dependencies.getLibraryVersion().getLibrary().getLibraryVendor();
            LibraryVendor newLibraryVendor = (LibraryVendor) libraryVendor.clone();
            session.save(newLibraryVendor);

            License license = dependencies.getLibraryVersion().getLibrary().getLicense();
            License newLicense = (License) license.clone();
            session.save(newLicense);

            Library library = dependencies.getLibraryVersion().getLibrary();
            Library newLibrary = (Library) library.clone();
            newLibrary.setLibraryVendor(newLibraryVendor);
            newLibrary.setLicense(newLicense);
            session.save(newLibrary);

            LibraryVersion libraryVersion = dependencies.getLibraryVersion();
            LibraryVersion newLibraryVersion = (LibraryVersion) libraryVersion.clone();
            newLibraryVersion.setLibrary(newLibrary);
            session.save(newLibraryVersion);

            ApplicationDependency applicationDependency = dependencies;
            ApplicationDependency newDependencies = (ApplicationDependency) applicationDependency.clone();
            newDependencies.setLibraryVersion(newLibraryVersion);
            newDependencies.setApplicationVersion(newApplicationVersion);
            session.save(newDependencies);
        }
        session.getTransaction().commit();
        session.close();
    }

}