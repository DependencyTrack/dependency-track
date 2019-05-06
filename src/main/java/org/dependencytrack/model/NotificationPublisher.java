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

import alpine.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.FetchGroups;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.UUID;

/**
 * Defines a Model class for notification publisher definitions.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@PersistenceCapable
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "name"),
                @Persistent(name = "description"),
                @Persistent(name = "publisherClass"),
                @Persistent(name = "template"),
                @Persistent(name = "templateMimeType"),
                @Persistent(name = "defaultPublisher"),
                @Persistent(name = "uuid"),
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class NotificationPublisher implements Serializable {

    private static final long serialVersionUID = -1274494967231181534L;

    /**
     * Defines JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "NAME", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String name;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DESCRIPTION")
    @Size(min = 0, max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String description;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PUBLISHER_CLASS", length = 1024, allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String publisherClass;

    @Persistent(defaultFetchGroup = "false")
    @Column(name = "TEMPLATE", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String template;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TEMPLATE_MIME_TYPE", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String templateMimeType;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "DEFAULT_PUBLISHER")
    private boolean defaultPublisher;

    @Persistent(defaultFetchGroup = "true", customValueStrategy = "uuid")
    @Unique(name = "NOTIFICATIONPUBLISHER_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    @NotNull
    public String getName() {
        return name;
    }

    public void setName(@NotNull String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @NotNull
    public String getPublisherClass() {
        return publisherClass;
    }

    public void setPublisherClass(@NotNull String publisherClass) {
        this.publisherClass = publisherClass;
    }

    public String getTemplate() {
        return template;
    }

    public void setTemplate(String template) {
        this.template = template;
    }

    @NotNull
    public String getTemplateMimeType() {
        return templateMimeType;
    }

    public void setTemplateMimeType(@NotNull String templateMimeType) {
        this.templateMimeType = templateMimeType;
    }

    public boolean isDefaultPublisher() {
        return defaultPublisher;
    }

    public void setDefaultPublisher(boolean defaultPublisher) {
        this.defaultPublisher = defaultPublisher;
    }

    @NotNull
    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(@NotNull UUID uuid) {
        this.uuid = uuid;
    }
}
