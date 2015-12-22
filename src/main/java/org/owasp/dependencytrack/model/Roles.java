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
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
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

        ROLE() { }

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
    @Column(name = "id", unique = true)
    @GeneratedValue
    private Integer id;

    /**
     * The role that is associated with a users.
     */
    @Column(name = "role", unique = true)
    private String role;


    /**
     * The User that are associated with this role.
     */
    @OneToMany(mappedBy = "roles", fetch = FetchType.EAGER)
    private Set<User> users= new HashSet<>();

    /**
     * The many to many relationship between roles and permissions .
     */
    @ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.ALL })
    @JoinTable(name = "ROLES_PERMISSIONS",
            joinColumns = { @JoinColumn(name = "ROLES_ID") },
            inverseJoinColumns = { @JoinColumn(name = "PERMISSIONS_ID") })
    private Set<Permissions> permissions = new HashSet<>();

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

    public Set<User> getUsers() {
        return users;
    }

    public void addUser(User user){
        this.users.add(user);
    }

    public Set<Permissions> getPermissions() {
        return permissions;
    }

    public void addPermission(Permissions permission){
        this.permissions.add(permission);
    }

    public void addPermissions(Collection<Permissions> toAdd){
        for (Permissions eachPermission : toAdd) {
            addPermission(eachPermission);
        }
    }

    public void addUsers(Collection<User> toAdd) {

        for (User user : toAdd) {
            users.add(user);
        }
    }


}
