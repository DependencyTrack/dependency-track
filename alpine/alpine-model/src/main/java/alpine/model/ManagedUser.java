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
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Discriminator;
import javax.jdo.annotations.Inheritance;
import javax.jdo.annotations.InheritanceStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import java.util.Date;

/**
 * Persistable object representing an ManagedUser.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@PersistenceCapable
@Inheritance(strategy = InheritanceStrategy.SUPERCLASS_TABLE)
@Discriminator(value = "MANAGED")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(value = {
        "username",
        "lastPasswordChange",
        "fullname",
        "email",
        "suspended",
        "forcePasswordChange",
        "nonExpiryPassword",
        "teams",
        "permissions" })
public class ManagedUser extends User {

    private static final long serialVersionUID = 7944779964068911025L;

    @Persistent
    @Column(name = "PASSWORD", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The password must not contain control characters")
    @JsonIgnore
    private String password;

    @Size(max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The new password must not contain control characters")
    private transient String newPassword; // not persisted

    @Size(max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The confirm password must not contain control characters")
    private transient String confirmPassword; // not persisted

    @Persistent
    @Column(name = "LAST_PASSWORD_CHANGE", allowsNull = "false")
    @NotNull
    private Date lastPasswordChange;

    @Persistent
    @Column(name = "FULLNAME")
    @Size(max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The full name must not contain control characters")
    private String fullname;

    @Persistent
    @Column(name = "SUSPENDED")
    private boolean suspended;

    @Persistent
    @Column(name = "FORCE_PASSWORD_CHANGE")
    private boolean forcePasswordChange;

    @Persistent
    @Column(name = "NON_EXPIRY_PASSWORD")
    private boolean nonExpiryPassword;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public Date getLastPasswordChange() {
        return lastPasswordChange;
    }

    public void setLastPasswordChange(Date lastPasswordChange) {
        this.lastPasswordChange = lastPasswordChange;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    public boolean isSuspended() {
        return suspended;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = suspended;
    }

    public boolean isForcePasswordChange() {
        return forcePasswordChange;
    }

    public void setForcePasswordChange(boolean forcePasswordChange) {
        this.forcePasswordChange = forcePasswordChange;
    }

    public boolean isNonExpiryPassword() {
        return nonExpiryPassword;
    }

    public void setNonExpiryPassword(boolean nonExpiryPassword) {
        this.nonExpiryPassword = nonExpiryPassword;
    }

}
