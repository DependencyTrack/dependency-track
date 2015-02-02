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

package org.owasp.dependencytrack.model;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "ROLES")
public class Roles {

    /**
     * Specify default roles
     */
    public static enum ROLE {
        /**
         * The name (as stored in the database) of the user role
         */
        USER,

        /**
         * The name (as stored in the database) of the moderator role
         */
        MODERATOR,

        /**
         * The name (as stored in the database) of the admin role
         */
        ADMIN;

        private ROLE() { }

        public static ROLE getRole(String roleName) {
            for (ROLE role: ROLE.values()) {
                if (roleName != null && role.name().equalsIgnoreCase(roleName)) {
                    return role;
                }
            }
            return null;
        }
    }

    /**
     * The unique identifier of the persisted object.
     */
    @Id
    @Column(name = "ID", unique = true)
    @GeneratedValue
    private Integer id;

    /**
     * The role that is associated with a users.
     */
    @Column(name = "ROLE", unique = true)
    private String role;


    /**
     * The User that are associated with this role.
     */
    @OneToMany(mappedBy = "roles", fetch = FetchType.EAGER)
    private Set<User> usr;

    /**
     * The many to many relationship between roles and permissions .
     */
    @ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.ALL })
    @JoinTable(name = "ROLES_PERMISSIONS",
            joinColumns = { @JoinColumn(name = "ROLES_ID") },
            inverseJoinColumns = { @JoinColumn(name = "PERMISSIONS_ID") })
    private Set<Permissions> perm = new HashSet<>();

    /**
     * Default Constructor.
     */
    public Roles() { }

    /**
     * Constructor specifying the role name.
     * @param rolename the name of the role
     */
    public Roles(String rolename) {
          role = rolename;
    }


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    //todo why is this shortened? Change it to User - also do Permissions
    public Set<User> getUsr() {
        return usr;
    }

    public void setUsr(Set<User> usr) {
        this.usr = usr;
    }

    public Set<Permissions> getPerm() {
        return perm;
    }

    public void setPerm(Set<Permissions> perm) {
        this.perm = perm;
    }

}
