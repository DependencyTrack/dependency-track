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

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.datanucleus.api.jdo.annotations.CreateTimestamp;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.NotPersistent;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.time.Instant;
import java.util.UUID;

/**
 * @since 5.0.0
 */
@PersistenceCapable(table = "COMPONENT_OCCURRENCE")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ComponentOccurrence {

    public record Identity(
            String location,
            Integer line,
            Integer offset,
            String symbol) {

        public static Identity of(final ComponentOccurrence occurrence) {
            return new Identity(
                    occurrence.getLocation(),
                    occurrence.getLine(),
                    occurrence.getOffset(),
                    occurrence.getSymbol());
        }

    }

    @PrimaryKey(name = "COMPONENT_OCCURRENCE_PK")
    @Persistent(customValueStrategy = "uuid-v7")
    @Column(name = "ID", sqlType = "UUID")
    private UUID id;

    @Persistent
    @ForeignKey(
            name = "COMPONENT_OCCURRENCE_COMPONENT_FK",
            deferred = "true",
            deleteAction = ForeignKeyAction.CASCADE,
            updateAction = ForeignKeyAction.NONE)
    @Index(name = "COMPONENT_OCCURRENCE_COMPONENT_ID_IDX")
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @JsonIgnore
    private Component component;

    @Persistent
    @Column(name = "LOCATION", jdbcType = "CLOB")
    private String location;

    @Persistent
    @Column(name = "LINE")
    private Integer line;

    @Persistent
    @Column(name = "OFFSET")
    private Integer offset;

    @Persistent
    @Column(name = "SYMBOL")
    private String symbol;

    @Persistent
    @CreateTimestamp
    @Column(name = "CREATED_AT")
    @JsonFormat(
            shape = JsonFormat.Shape.NUMBER_INT,
            without = JsonFormat.Feature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS)
    private Instant createdAt;

    @NotPersistent
    @JsonIgnore
    private transient Integer totalCount;

    public UUID getId() {
        return id;
    }

    public void setId(final UUID id) {
        this.id = id;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(final Component component) {
        this.component = component;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(final String location) {
        this.location = location;
    }

    public Integer getLine() {
        return line;
    }

    public void setLine(final Integer line) {
        this.line = line;
    }

    public Integer getOffset() {
        return offset;
    }

    public void setOffset(final Integer offset) {
        this.offset = offset;
    }

    public String getSymbol() {
        return symbol;
    }

    public void setSymbol(final String symbol) {
        this.symbol = symbol;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(final Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Integer getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(final Integer totalCount) {
        this.totalCount = totalCount;
    }

}
