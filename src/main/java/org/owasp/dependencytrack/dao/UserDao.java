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

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * Users: nchitlurnavakiran
 * Date: 8/14/13
 * Time: 11:17 AM
 * To change this template use File | Settings | File Templates.
 */
@Repository
public class UserDao {

    /**
     * The Hibernate SessionFactory
     */
    @Autowired
    private SessionFactory sessionFactory;


    public void registerUser(String username,String password)
    {
        RandomNumberGenerator rng = new SecureRandomNumberGenerator();
        Object salt = rng.nextBytes();

        String hashedPasswordBase64 = new Sha256Hash(password,salt.toString()).toBase64();

        Query query = sessionFactory.getCurrentSession().createQuery("FROM Roles as r where r.role  =:role");
        query.setParameter("role","user");

        Users users = new Users();
        users.setPassword(hashedPasswordBase64);
        users.setUsername(username);
        users.setCheckvalid(false);
        users.setRoles((Roles)query.list().get(0));
        users.setPassword_salt(salt.toString());
        sessionFactory.getCurrentSession().save(users);
    }

    public String hashpwd(String username, String password)
    {
        Query query = sessionFactory.getCurrentSession().createQuery("FROM Users where username =:usrn");
        query.setParameter("usrn",username);
        if(query.list().isEmpty())
        {
            return null;
        }
        Users users = (Users) query.list().get(0);
        String hashedPasswordBase64 = new Sha256Hash(password,users.getPassword_salt()).toBase64();
        return hashedPasswordBase64;
    }

    public List<Users> accountManagement()
    {
        Query query = sessionFactory.getCurrentSession().createQuery("FROM Users ");

        List<Users> userlist = query.list();

        return userlist;
    }

    public void validateuser(int userid)
    {
        Query query = sessionFactory.getCurrentSession().createQuery("select usr.checkvalid FROM Users as usr where usr.id= :userid");
        query.setParameter("userid",userid);

        Boolean currentState = (Boolean) query.list().get(0);

        if(currentState)
        {
            query = sessionFactory.getCurrentSession().createQuery("update Users as usr set usr.checkvalid  = :checkinvalid" +
                    " where usr.id = :userid");
            query.setParameter("checkinvalid", false);
            query.setParameter("userid",userid );
            query.executeUpdate();
}
        else
        {
            query = sessionFactory.getCurrentSession().createQuery("update Users as usr set usr.checkvalid  = :checkvalid" +
                    " where usr.id = :userid");
            query.setParameter("checkvalid", true);
            query.setParameter("userid",userid );
            query.executeUpdate();
        }
        }


    public void deleteUser(int userid)
    {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        Query query = sessionFactory.getCurrentSession().createQuery(" FROM Users as usr where usr.id= :userid");
        query.setParameter("userid",userid);

        Users curUser = (Users) query.list().get(0);

        session.delete(curUser);
        session.getTransaction().commit();
        session.close();
    }

    public List<Roles> getRoleList()
    {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        Query query = sessionFactory.getCurrentSession().createQuery(" FROM Roles  ");

        ArrayList<Roles> rolelist = (ArrayList<Roles>) query.list();
        session.close();
        return  rolelist;
    }

    public void changeUserRole(int userid,int role)
    {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();

        Query query = sessionFactory.getCurrentSession().createQuery("update Users as usr set usr.roles.id  = :role" +
                " where usr.id = :userid");
        query.setParameter("role", role);
        query.setParameter("userid",userid );
        query.executeUpdate();

        session.getTransaction().commit();
        session.close();
    }
 }
