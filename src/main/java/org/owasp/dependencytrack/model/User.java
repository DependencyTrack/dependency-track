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
package org.owasp.dependencytrack.model;

import javax.persistence.*;

@Entity
@Table(name = "users")
public final class User {

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "id")
    @GeneratedValue
    private Integer id;

    /**
     * The name users use to logon.
     */
    @Column(name = "username", unique = true)
    private String username;

    /**
     * The password associated with the username.
     */
    @Column(name = "password")
    private String password;

    /**
     * Admin validates a registered user and gives him access to the website
     */
    @Column(name = "checkvalid")
    private boolean checkvalid;  //todo delete this field

    /**
     * Specifies if the username is a pointer to an external LDAP entity
     */
    @Column(name = "isldap")
    private boolean isldap;

    /**
     * The license the library is licensed under.
     */
    @ManyToOne
    @JoinColumn(name = "roleid")
    @OrderBy
    private Roles roles;

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

    public boolean isCheckvalid() {
        return checkvalid;
    }

    public void setCheckvalid(boolean checkvalid) {
        this.checkvalid = checkvalid;
    }

    public boolean isLdap() {
        return isldap;
    }

    public void setIsLdap(boolean isldap) {
        this.isldap = isldap;
    }

    public Roles getRoles() {
        return roles;
    }

    public void setRoles(Roles roles) {
        this.roles = roles;
    }
}
