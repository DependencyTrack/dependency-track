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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

/**
 * Model class for tracking the importing of VEX documents.
 *
 * @author Steve Springett
 * @since 4.5.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Vex implements Serializable {

    private static final long serialVersionUID = -4378439983100141050L;

    public enum Format {
        CYCLONEDX("CycloneDX", "CycloneDX BOM Standard");

        private final String formatShortName;
        private final String formatLongName;

        Format(final String formatShortName, final String formatLongName) {
            this.formatShortName = formatShortName;
            this.formatLongName = formatLongName;
        }

        public String getFormatShortName() {
            return formatShortName;
        }

        public String getFormatLongName() {
            return formatLongName;
        }
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "IMPORTED", allowsNull = "false")
    @NotNull
    private Date imported;

    @Persistent
    @Column(name = "VEX_FORMAT")
    private String vexFormat;

    @Persistent
    @Column(name = "SPEC_VERSION")
    private String specVersion;

    @Persistent
    @Column(name = "VEX_VERSION")
    private Integer vexVersion;

    @Persistent
    @Column(name = "SERIAL_NUMBER")
    private String serialNumber;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @NotNull
    private Project project;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "VEX_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Date getImported() {
        return imported;
    }

    public void setImported(Date imported) {
        this.imported = imported;
    }

    public String getVexFormat() {
        return vexFormat;
    }

    public void setVexFormat(Format format) {
        this.vexFormat = format.formatShortName;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    public Integer getVexVersion() {
        return vexVersion;
    }

    public void setVexVersion(Integer vexVersion) {
        this.vexVersion = vexVersion;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
