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

import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * The ViolationAnalysisComment model provides zero or more comments for a human
 * auditing decision ({@link ViolationAnalysis}).
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ViolationAnalysisComment implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true", dependent = "true")
    @Column(name = "VIOLATIONANALYSIS_ID", allowsNull = "false")
    @NotNull
    @JsonIgnore
    private ViolationAnalysis violationAnalysis;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TIMESTAMP", allowsNull = "false")
    @NotNull
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date timestamp;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMMENT", jdbcType = "CLOB", allowsNull = "false")
    @NotNull
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String comment;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMMENTER")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String commenter;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public ViolationAnalysis getViolationAnalysis() {
        return violationAnalysis;
    }

    public void setViolationAnalysis(ViolationAnalysis violationAnalysis) {
        this.violationAnalysis = violationAnalysis;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getCommenter() {
        return commenter;
    }

    public void setCommenter(String commenter) {
        this.commenter = commenter;
    }
}
