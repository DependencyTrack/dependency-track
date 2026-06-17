/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Discriminator;
import javax.jdo.annotations.DiscriminatorStrategy;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Inheritance;
import javax.jdo.annotations.InheritanceStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.security.Principal;
import java.util.List;

@PersistenceCapable(table = "USER")
@Discriminator(column = "TYPE", strategy = DiscriminatorStrategy.VALUE_MAP)
@Inheritance(strategy = InheritanceStrategy.NEW_TABLE)
public abstract class User implements Serializable, Principal {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(table = "USERS_TEAMS", defaultFetchGroup = "true")
    @Join(column = "USER_ID", primaryKey = "USERS_TEAMS_PK", foreignKey = "USERS_TEAMS_USER_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Element(column = "TEAM_ID", foreignKey = "USERS_TEAMS_TEAM_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE)
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    private List<Team> teams;

    @Persistent(table = "USERS_PERMISSIONS", defaultFetchGroup = "true")
    @Join(column = "USER_ID", primaryKey = "USERS_PERMISSIONS_PK", foreignKey = "USERS_PERMISSIONS_USER_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Element(column = "PERMISSION_ID", foreignKey = "USERS_PERMISSIONS_PERMISSION_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE)
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    private List<Permission> permissions;

    @Persistent
    @Unique(name = "USER_USERNAME_IDX")
    @Column(name = "USERNAME")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The username must not contain control characters")
    private String username;

    @Persistent
    @Column(name = "EMAIL", allowsNull = "true")
    @Size(max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The email address must not contain control characters")
    private String email;

    /**
     * The database id of the principal.
     * @return a long of the unique id
     */
    public long getId() {
        return id;
    }

    /**
     * Specifies the database id of the principal.
     * @param id a long of the unique id
     */
    public void setId(long id) {
        this.id = id;
    }

    /**
     * The username of the principal.
     * @return a String of the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Specifies the username of the principal.
     * @param username the username of the principal
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * The email address of the principal.
     * @return a String of the email address
     */
    public String getEmail() {
        return email;
    }

    /**
     * Specifies the email address of the principal.
     * @param email the email address of the principal
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * A list of teams the principal is a member of.
     * @return a List of Team objects
     */
    public List<Team> getTeams() {
        return teams;
    }

    /**
     * Specifies the teams the principal is a member of.
     * @param teams a List of Team objects
     */
    public void setTeams(List<Team> teams) {
        this.teams = teams;
    }

    /**
     * A list of permissions the principal has.
     * @return a List of Permissions objects
     */
    public List<Permission> getPermissions() {
        return permissions;
    }

    /**
     * Specifies the permissions the principal should have.
     * @param permissions a List of Permission objects
     */
    public void setPermissions(List<Permission> permissions) {
        this.permissions = permissions;
    }

    /**
     * Do not use - only here to satisfy Principal implementation requirement.
     * @deprecated use {@link #getUsername()}
     * @return the value of {@link #getUsername()}
     */
    @Deprecated
    @JsonIgnore
    public String getName() {
        return getUsername();
    }

}
