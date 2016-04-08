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

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;

public abstract class BaseDao implements IBaseDao {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BaseDao.class);

    /**
     * The Hibernate SessionFactory
     */
    @Autowired
    private SessionFactory sessionFactory;

    private List<Session> manuallyOpenedSessions = new ArrayList<>();

    public BaseDao() {
    }

    public BaseDao(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public Session getSession() {
        try {
            return sessionFactory.getCurrentSession();
        } catch (HibernateException e) {
            LOGGER.debug("Unable to obtain the current hibernate session");
        }
        // This should only be invoked during unit tests.
        // todo: figure out a different way to get unit tests working without manually opening a session like this. Ugly!
        LOGGER.debug("Attempting to open a new hibernate session");
        Session session = sessionFactory.openSession();
        manuallyOpenedSessions.add(session);
        return session;
    }

    public int getCount(Session session, Class clazz) {
        return ((Long) session.createQuery("select count(*) from " + clazz.getSimpleName()).uniqueResult()).intValue();
    }

    public void cleanup() {
        for (Session session: manuallyOpenedSessions) {
            if(session != null && session.isOpen()) {
                LOGGER.debug("Closing hibernate session");
                session.flush();
                session.close();
            }
        }
        manuallyOpenedSessions = new ArrayList<>();
    }

}
