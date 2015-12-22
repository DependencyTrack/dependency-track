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
import java.util.HashSet;
import java.util.Set;


@Entity
@Table(name = "permissions")
public class Permissions {
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
    @Column(name = "permissionname", unique = true)
    private String permissionname;

    /**
     * The roles associated with this permission.
     */
    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "permissions")
    private Set<Roles> maprole = new HashSet<>();

    /**
     * Default Constructor.
     */
    public Permissions() { }

    /**
     * Constructor specifying the permission name.
     * @param permissionname the name of the permission
     */
    public Permissions(String permissionname) {
        this.permissionname = permissionname;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getPermissionname() {
        return permissionname;
    }

    public void setPermissionname(String permissionname) {
        this.permissionname = permissionname;
    }

    public Set<Roles> getMaprole() {
        return maprole;
    }

    public void setMaprole(Set<Roles> maprole) {
        this.maprole = maprole;
    }

}
