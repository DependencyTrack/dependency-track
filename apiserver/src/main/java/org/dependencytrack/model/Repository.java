/*
 * This file is part of Dependency-Track.
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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.UUID;

/**
 * Tracks third-party metadata about component groups from external repositories
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@PersistenceCapable(table = "REPOSITORY")
@Unique(name = "REPOSITORY_COMPOUND_IDX", members = {"type", "identifier"})
public class Repository implements Serializable {

    private static final long serialVersionUID = -3875882921059813747L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TYPE", jdbcType = "VARCHAR", allowsNull = "false")
    private RepositoryType type;

    @Persistent
    @Column(name = "IDENTIFIER", allowsNull = "false")
    private String identifier;

    @Persistent
    @Column(name = "URL")
    private String url;

    @Persistent
    @Column(name = "RESOLUTION_ORDER")
    private int resolutionOrder;

    @Persistent
    @Column(name = "ENABLED")
    private boolean enabled;

    @Persistent
    @Column(name = "INTERNAL")
    private Boolean internal; // New column, must allow nulls on existing databases

    @Persistent
    @Column(name = "AUTHENTICATIONREQUIRED", allowsNull = "false", defaultValue = "false")
    private boolean authenticationRequired;

    @Persistent
    @Column(name = "USERNAME")
    private String username;

    @Persistent
    @Column(name = "PASSWORD")
    private String password;

    @Persistent(customValueStrategy = "uuid")
    @Index(name = "REPOSITORY_UUID_IDX") // Cannot be @Unique. Microsoft SQL Server throws an exception
    @Column(name = "UUID", sqlType = "UUID", allowsNull = "true")
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public RepositoryType getType() {
        return type;
    }

    public void setType(RepositoryType type) {
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getResolutionOrder() {
        return resolutionOrder;
    }

    public void setResolutionOrder(int resolutionOrder) {
        this.resolutionOrder = resolutionOrder;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean isInternal() {
        return internal;
    }

    public boolean isAuthenticationRequired() {
        return authenticationRequired;
    }

    public void setAuthenticationRequired(boolean authenticationRequired) {
        this.authenticationRequired = authenticationRequired;
    }

    public void setInternal(Boolean internal) {
        this.internal = internal;
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

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
