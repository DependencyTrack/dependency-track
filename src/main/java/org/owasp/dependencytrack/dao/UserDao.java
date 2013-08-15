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
import org.hibernate.SessionFactory;
import org.owasp.dependencytrack.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

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


        Users users = new Users();
        users.setPassword(hashedPasswordBase64);
        users.setUsername(username);
        users.setPassword_salt(salt.toString());
        sessionFactory.getCurrentSession().save(users);
    }

    public String hashpwd(String username, String password)
    {
        Query query = sessionFactory.getCurrentSession().createQuery("FROM Users where username =:usrn");
        query.setParameter("usrn",username);

        Users users = (Users) query.list().get(0);

        System.out.println(users.getPassword_salt());



        String hashedPasswordBase64 = new Sha256Hash(password,users.getPassword_salt()).toBase64();

        System.out.println("the hashed password is"+ hashedPasswordBase64 );

        return hashedPasswordBase64;
    }
}
