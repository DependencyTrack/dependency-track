/*
 * Copyright 2013 Axway
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

    public void deleteApplicationVersion(Integer id) {
        /*Session session = sessionFactory.openSession();
        session.beginTransaction();*/
        ApplicationVersion applicationVersion = (ApplicationVersion) sessionFactory
                .getCurrentSession().load(ApplicationVersion.class, id);
        Query query = sessionFactory.getCurrentSession().createQuery("from ApplicationDependency where applicationVersion=:appver");
        query.setParameter("appver", applicationVersion);

        if(!query.list().isEmpty())
        {
            List <ApplicationDependency> applicationDependencies = query.list();
            for (ApplicationDependency appdep: applicationDependencies)
            {
                sessionFactory.getCurrentSession().delete(appdep);
            }
        }

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

    public void cloneApplication(int applicationid, String applicationname)
    {
        Query query = sessionFactory.getCurrentSession().createQuery("from Application where id=:id");
        query.setParameter("id", applicationid);

        Application findapplication = (Application)query.list().get(0);

        query = sessionFactory.getCurrentSession().createQuery("from ApplicationVersion AS appver where appver.application=:findapplication");
        query.setParameter("findapplication", findapplication);

        List<ApplicationVersion>applicationVersions = query.list();

        Session session = sessionFactory.openSession();
        session.beginTransaction();

        Application application = new Application();
        application.setName(applicationname);
        session.save(application);

        for (ApplicationVersion appver : applicationVersions)
        {
            query = sessionFactory.getCurrentSession().createQuery("from ApplicationDependency AS appdep where appdep.applicationVersion=:id");
            query.setParameter("id", appver);

            List<ApplicationDependency>applicationDependencies = query.list();

            ApplicationVersion applicationVersion = appver;
            ApplicationVersion newApplicationVersion = (ApplicationVersion) applicationVersion.clone();
            newApplicationVersion.setApplication(application);
            session.save(newApplicationVersion);

            for (ApplicationDependency appdep : applicationDependencies)
            {
                ApplicationDependency applicationDependency = appdep;
                ApplicationDependency newDependencies = (ApplicationDependency) applicationDependency.clone();
                newDependencies.setApplicationVersion(newApplicationVersion);
                session.save(newDependencies);
            }

        }
        session.getTransaction().commit();
        session.close();

    }



    public void cloneApplicationVersion(int applicationid, String newversion, String curappver)
    {
        Session session = sessionFactory.openSession();
        session.beginTransaction();

        Query query = session.createQuery("from Application AS apps where apps.id=:findapplication");
        query.setParameter("findapplication",applicationid);

        Application app = (Application) query.list().get(0);

        query = session.createQuery("from ApplicationVersion AS appver where appver.application=:findapplication and appver.version=:curappver");
        query.setParameter("findapplication",app);
        query.setParameter("curappver",curappver);

        ApplicationVersion applicationVersion = (ApplicationVersion)query.list().get(0);
        ApplicationVersion newApplicationVersion = (ApplicationVersion) applicationVersion.clone();
        newApplicationVersion.setVersion(newversion);
        session.save(newApplicationVersion);

        query = session.createQuery("from ApplicationDependency AS appdep where appdep.applicationVersion=:findappverr");
        query.setParameter("findappverr",applicationVersion);


        List<ApplicationDependency> applicationDependencies = query.list();


        for (ApplicationDependency appdep : applicationDependencies)
        {
            ApplicationDependency applicationDependency = appdep;
            ApplicationDependency newDependencies = (ApplicationDependency) applicationDependency.clone();
            newDependencies.setApplicationVersion(newApplicationVersion);
            session.save(newDependencies);
        }


        session.getTransaction().commit();
        session.close();

    }

     public void updateApplicationVersion(int id, String appversion)
     {
         Query query = sessionFactory.getCurrentSession().createQuery(
                 "update ApplicationVersion set version=:ver " + "where id=:appverid");

         query.setParameter("ver", appversion);
         query.setParameter("appverid", id);
         int result = query.executeUpdate();

     }



}