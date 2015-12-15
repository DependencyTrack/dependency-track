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
import org.mindrot.jbcrypt.BCrypt;
import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.owasp.dependencytrack.util.session.DBSessionTask;
import org.owasp.dependencytrack.util.session.DBSessionTaskReturning;
import org.owasp.dependencytrack.util.session.DBSessionTaskRunner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UserDaoImpl extends DBSessionTaskRunner implements UserDao {

    /**
     * The number of Bcrypt rounds to use when hashing passwords
     */
    @Value("${crypto.bcryptRounds}")
    private Integer bcryptRounds;

    @Override
    @Transactional
    public void registerUser(final String username, final boolean isLdap, final String password, final Integer role) {

        dbRun(new DBSessionTask() {
            @Override
            public void run(Session session) {
                Query query;
                if (role == null) {
                    query = session.createQuery("FROM Roles as r where r.role  =:role");
                    query.setParameter("role", "user");
                } else {
                    query = session.createQuery("FROM Roles as r where r.id  =:role");
                    query.setParameter("role", role);
                }

                final User user = new User();
                if (isLdap) {
                    user.setIsLdap(true);
                } else {

                    String gensalt = BCrypt.gensalt(bcryptRounds);
                    try{
                        String hashpw = BCrypt.hashpw(password, gensalt);
                        user.setPassword(hashpw);
                    }catch (Throwable t){
                        t.printStackTrace();
                    }
                    user.setIsLdap(false);
                }
                user.setUsername(username);
                user.setCheckvalid(false);
                user.setRoles((Roles) query.list().get(0));
                session.save(user);
            }
        });
    }

    @Override
    @SuppressWarnings("unchecked")
    @Transactional
    public List<User> accountManagement() {
        return dbRun(new DBSessionTaskReturning<List<User>>() {
            @Override
            public List<User> run(Session session) {
                return session.createQuery("FROM User order by username").list();
            }
        });
    }

    @Override
    @Transactional
    public void validateuser(final int userid) {
        dbRun(new DBSessionTask() {
            @Override
            public void run(Session session) {
                Query query = session.createQuery("select usr.checkvalid FROM User as usr where usr.id= :userid");
                query.setParameter("userid", userid);

                final Boolean currentState = (Boolean) query.list().get(0);

                if (currentState) {
                    query = session.createQuery("update User as usr set usr.checkvalid  = :checkinvalid"
                            + " where usr.id = :userid");
                    query.setParameter("checkinvalid", false);
                    query.setParameter("userid", userid);
                    query.executeUpdate();
                } else {
                    query = session.createQuery("update User as usr set usr.checkvalid  = :checkvalid"
                            + " where usr.id = :userid");
                    query.setParameter("checkvalid", true);
                    query.setParameter("userid", userid);
                    query.executeUpdate();
                }
            }
        });
    }

    @Override
    @Transactional
    public void deleteUser(final int userid) {
        dbRun(new DBSessionTask() {
            @Override
            public void run(Session session) {
                final Query query = session.createQuery(" FROM User as usr where usr.id= :userid");
                query.setParameter("userid", userid);

                final User curUser = (User) query.list().get(0);

                session.delete(curUser);
            }
        });
    }

    @Override
    @SuppressWarnings("unchecked")
    @Transactional
    public List<Roles> getRoleList() {

        return dbRun(new DBSessionTaskReturning<List<Roles>>() {
            @Override
            public List<Roles> run(Session session) {
                return (ArrayList<Roles>) session.createQuery(" FROM Roles  ").list();
            }
        });
    }

    @Override
    @Transactional
    public void changeUserRole(final int userid, final int role) {
        dbRun(new DBSessionTask() {
            @Override
            public void run(Session session) {
                final Query query = session.createQuery("update User as usr set usr.roles.id  = :role"
                        + " where usr.id = :userid");
                query.setParameter("role", role);
                query.setParameter("userid", userid);
                query.executeUpdate();
            }
        });

    }

    @Override
    @Transactional
    public boolean confirmUserPassword(final String username, String password) {
        final User user = dbRun(new DBSessionTaskReturning<User>() {
            @Override
            public User run(Session session) {
                final Query query = session.createQuery("FROM User as usr where usr.username = :username and usr.isldap = :isldap");
                query.setParameter("username", username);
                query.setParameter("isldap", false);

                return (User) query.uniqueResult();
            }
        });
        return user != null && BCrypt.checkpw(password, user.getPassword());
    }

    @Override
    @Transactional
    public boolean changePassword(final String username, final String password) {
        return dbRun(new DBSessionTaskReturning<Boolean>() {
            @Override
            public Boolean run(Session session) {
                final Query query = session.createQuery("update User as usr set usr.password = :password"
                        + " where usr.username = :username and usr.isldap = :isldap");
                final String hashedPw = BCrypt.hashpw(password, BCrypt.gensalt(bcryptRounds));
                query.setParameter("password", hashedPw);
                query.setParameter("username", username);
                query.setParameter("isldap", false);
                final int updates = query.executeUpdate();
                return updates == 1;
            }
        });
    }

    @Override
    @Transactional
    public boolean isLdapUser(final String username) {

        final User user = dbRun(new DBSessionTaskReturning<User>() {
            @Override
            public User run(Session session) {
                final Query query = session.createQuery("FROM User as usr where usr.username = :username");
                query.setParameter("username", username);

                return (User) query.uniqueResult();
            }
        });

        return user != null && user.isLdap();
    }
}
