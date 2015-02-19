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
import org.mindrot.jbcrypt.BCrypt;
import org.owasp.dependencytrack.Config;
import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UserDao {

    /**
     * The Hibernate SessionFactory
     */
    @Autowired
    private SessionFactory sessionFactory;

    /**
     * Dependency-Track's centralized Configuration class
     */
    @Autowired
    private Config config;

    public void registerUser(String username, boolean isLdap, String password, Integer role) {
        Query query;
        if (role == null) {
            query = sessionFactory.getCurrentSession().createQuery("FROM Roles as r where r.role  =:role");
            query.setParameter("role", "user");
        } else {
            query = sessionFactory.getCurrentSession().createQuery("FROM Roles as r where r.id  =:role");
            query.setParameter("role", role);
        }


        final User user = new User();
        if (isLdap) {
            user.setIsLdap(true);
        } else {
            user.setPassword(BCrypt.hashpw(password, BCrypt.gensalt(config.getBcryptRounds())));
            user.setIsLdap(false);
        }
        user.setUsername(username);
        user.setCheckvalid(false);
        user.setRoles((Roles) query.list().get(0));
        sessionFactory.getCurrentSession().save(user);
    }

    @SuppressWarnings("unchecked")
    public List<User> accountManagement() {
        final Query query = sessionFactory.getCurrentSession().createQuery("FROM User order by username");
        return query.list();
    }

    public void validateuser(int userid) {
        Query query = sessionFactory.getCurrentSession().createQuery("select usr.checkvalid FROM User as usr where usr.id= :userid");
        query.setParameter("userid", userid);

        final Boolean currentState = (Boolean) query.list().get(0);

        if (currentState) {
            query = sessionFactory.getCurrentSession().createQuery("update User as usr set usr.checkvalid  = :checkinvalid"
                    + " where usr.id = :userid");
            query.setParameter("checkinvalid", false);
            query.setParameter("userid", userid);
            query.executeUpdate();
        } else {
            query = sessionFactory.getCurrentSession().createQuery("update User as usr set usr.checkvalid  = :checkvalid"
                    + " where usr.id = :userid");
            query.setParameter("checkvalid", true);
            query.setParameter("userid", userid);
            query.executeUpdate();
        }
    }

    public void deleteUser(int userid) {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        final Query query = sessionFactory.getCurrentSession().createQuery(" FROM User as usr where usr.id= :userid");
        query.setParameter("userid", userid);

        final User curUser = (User) query.list().get(0);

        session.delete(curUser);
        session.getTransaction().commit();
        session.close();
    }

    @SuppressWarnings("unchecked")
    public List<Roles> getRoleList() {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        final Query query = sessionFactory.getCurrentSession().createQuery(" FROM Roles  ");

        final ArrayList<Roles> rolelist = (ArrayList<Roles>) query.list();
        session.close();
        return rolelist;
    }

    public void changeUserRole(int userid, int role) {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        final Query query = sessionFactory.getCurrentSession().createQuery("update User as usr set usr.roles.id  = :role"
                + " where usr.id = :userid");
        query.setParameter("role", role);
        query.setParameter("userid", userid);
        query.executeUpdate();

        session.getTransaction().commit();
        session.close();
    }

    public boolean confirmUserPassword(String username, String password) {
        final Session session = sessionFactory.openSession();
        final Query query = session.createQuery("FROM User as usr where usr.username = :username and usr.isldap = :isldap");
        query.setParameter("username", username);
        query.setParameter("isldap", false);
        final User user = (User) query.uniqueResult();
        return user != null && BCrypt.checkpw(password, user.getPassword());
    }

    public boolean changePassword(String username, String password) {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();
        final Query query = sessionFactory.getCurrentSession().createQuery("update User as usr set usr.password = :password"
                + " where usr.username = :username and usr.isldap = :isldap");
        final String hashedPw = BCrypt.hashpw(password, BCrypt.gensalt(config.getBcryptRounds()));
        query.setParameter("password", hashedPw);
        query.setParameter("username", username);
        query.setParameter("isldap", false);
        final int updates = query.executeUpdate();
        session.getTransaction().commit();
        session.close();
        return updates == 1;
    }

    public boolean isLdapUser(String username) {
        final Session session = sessionFactory.openSession();
        final Query query = session.createQuery("FROM User as usr where usr.username = :username");
        query.setParameter("username", username);
        final User user = (User) query.uniqueResult();
        return user != null && user.isLdap();
    }
}
