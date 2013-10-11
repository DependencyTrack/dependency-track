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

package org.owasp.dependencytrack.model;

import org.hibernate.annotations.Type;

import javax.persistence.*;

/**
 * Created with IntelliJ IDEA.
 * Users: nchitlurnavakiran
 * Date: 8/14/13
 * Time: 10:59 AM
 * To change this template use File | Settings | File Templates.
 */
@Entity
@Table(name = "USERS")
public final class Users {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "ID")
    @GeneratedValue
    private Integer id;

    /**
     * The name users use to logon.
     */
    @Column(name = "USERNAME",unique=true)
    private String username;

    /**
     * The password associated with the username.
     */
    @Column(name = "PASSWORD")
    private String password;

    /**
     * The salt associated with each password.
     */
    @Column(name = "PASSWORD_SALT")
    private String password_salt;

    /**
     * Admin validates a registered user and gives him access to the website
     */
    @Column(name = "CHECKVALID")
    private boolean checkvalid ;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword_salt() {
        return password_salt;
    }

    public void setPassword_salt(String password_salt) {
        this.password_salt = password_salt;
    }

    public boolean isCheckvalid() {
        return checkvalid;
    }

    public void setCheckvalid(boolean checkvalid) {
        this.checkvalid = checkvalid;
    }
}
