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
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationDependency;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class ApplicationDao {

    @Autowired
    private SessionFactory sessionFactory;

    public List<Application> listApplications() {
        Query query = sessionFactory.getCurrentSession().createQuery("FROM Application");
        return query.list();
    }

    public void addApplication(Application application, String version) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        session.save(application);

        ApplicationVersion applicationVersion = new ApplicationVersion();
        applicationVersion.setVersion(version);
        applicationVersion.setApplication(application);

        session.save(applicationVersion);
        session.getTransaction().commit();
        session.close();
    }

    public void updateApplication(int id, String name) {
        Query query = sessionFactory.getCurrentSession().createQuery(
                "update Application set name=:name " + "where id=:id");

        query.setParameter("name", name);
        query.setParameter("id", id);
        query.executeUpdate();
    }

    public void deleteApplication(int id) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        Application curapp = (Application) session.load(Application.class, id);

        Query query = session.createQuery(
                "from ApplicationVersion " + "where application=:curapp");
        query.setParameter("curapp", curapp);

        List <ApplicationVersion> applicationVersions = query.list();

        for(ApplicationVersion curver:applicationVersions)
        {

        query = session.createQuery(
                "from ApplicationDependency " + "where applicationVersion=:curver");

        query.setParameter("curver",curver);
        List <ApplicationDependency> applicationDependency;


        if (!query.list().isEmpty()) {

            applicationDependency =   query.list();
            for(ApplicationDependency dependency: applicationDependency)
            {
               session.delete(dependency);
            }
        }
            session.delete(curver);
        }
        session.delete(curapp);
        session.getTransaction().commit();
        session.close();
}


    public List<Application> searchApplications(int libid,int libverid)
    {

        Query query = sessionFactory.getCurrentSession().createQuery("FROM LibraryVersion where id=:libverid");

        query.setParameter("libverid",libverid);
        LibraryVersion libraryVersion = (LibraryVersion) query.list().get(0);

        System.out.println(libraryVersion.getId()+""+libraryVersion.getLibraryversion());
        System.out.println("one size "+query.list().size());

        query = sessionFactory.getCurrentSession().createQuery("FROM ApplicationDependency where libraryVersion=:libver");
        query.setParameter("libver",libraryVersion);

        System.out.println("two "+query.list().size());

       List< ApplicationDependency >apdep= query.list();
        List<Integer> ids = new ArrayList<Integer>();

        for(ApplicationDependency appdep:apdep)
        {
            ids.add(appdep.getApplicationVersion().getId());
        }


        query = sessionFactory.getCurrentSession().createQuery(" FROM ApplicationVersion as appver where appver.id in (:appverid)");
        query.setParameterList("appverid", ids);


        System.out.println("size"+ query.list().size());
        List<ApplicationVersion> newappver= query.list();

        ArrayList <Application> newapp= new ArrayList<Application>();

        for(ApplicationVersion version :newappver)
        {
            newapp.add(version.getApplication());
        }


        return newapp;
    }
}