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
package org.dependencytrack.resources.v1.vo;

import org.dependencytrack.model.Tag;
import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.List;

/**
 * Defines a custom request object used when uploading bill-of-material (bom) documents.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class BomSubmitRequest {

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The project must be a valid 36 character UUID")
    private final String project;

    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The project name may only contain printable characters")
    private final String projectName;

    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The project version may only contain printable characters")
    private final String projectVersion;

    private final List<Tag> projectTags;

    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The parent UUID must be a valid 36 character UUID")
    private final String parentUUID;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The parent name may only contain printable characters")
    private final String parentName;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The parent version may only contain printable characters")
    private final String parentVersion;

    @NotNull
    @Pattern(regexp = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", message = "The BOM must be Base64 encoded")
    private final String bom;

    private final boolean autoCreate;

    public BomSubmitRequest(String project,
                            String projectName,
                            String projectVersion,
                            List<Tag> projectTags,
                            boolean autoCreate,
                            String bom) {
        this(project, projectName, projectVersion, projectTags, autoCreate, null, null, null, bom);
    }

    @JsonCreator
    public BomSubmitRequest(@JsonProperty(value = "project") String project,
                            @JsonProperty(value = "projectName") String projectName,
                            @JsonProperty(value = "projectVersion") String projectVersion,
                            @JsonProperty(value = "projectTags") List<Tag> projectTags,
                            @JsonProperty(value = "autoCreate") boolean autoCreate,
                            @JsonProperty(value = "parentUUID") String parentUUID,
                            @JsonProperty(value = "parentName") String parentName,
                            @JsonProperty(value = "parentVersion") String parentVersion,
                            @JsonProperty(value = "bom", required = true) String bom) {
        this.project = project;
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.projectTags = projectTags;
        this.autoCreate = autoCreate;
        this.parentUUID = parentUUID;
        this.parentName = parentName;
        this.parentVersion = parentVersion;
        this.bom = bom;
    }

    @Schema(example = "38640b33-4ba9-4733-bdab-cbfc40c6f8aa")
    public String getProject() {
        return project;
    }

    @Schema(example = "Example Application")
    public String getProjectName() {
        return projectName;
    }

    @Schema(example = "1.0.0")
    public String getProjectVersion() {
        return projectVersion;
    }

    @Schema(description = "Overwrite project tags")
    public List<Tag> getProjectTags() {
        return projectTags;
    }

    @Schema(example = "5341f53c-611b-4388-9d9c-731026dc5eec")
    public String getParentUUID() {
        return parentUUID;
    }

    @Schema(example = "Example Application Parent")
    public String getParentName() {
        return parentName;
    }

    @Schema(example = "1.0.0")
    public String getParentVersion() {
        return parentVersion;
    }

    public boolean isAutoCreate() {
        return autoCreate;
    }

    @Schema(
            description = "Base64 encoded BOM",
            required = true,
            example = """
                    ewogICJib21Gb3JtYXQiOiAiQ3ljbG9uZURYIiwKICAic3BlY1ZlcnNpb24iOiAi\
                    MS40IiwKICAiY29tcG9uZW50cyI6IFsKICAgIHsKICAgICAgInR5cGUiOiAibGli\
                    cmFyeSIsCiAgICAgICJuYW1lIjogImFjbWUtbGliIiwKICAgICAgInZlcnNpb24i\
                    OiAiMS4wLjAiCiAgICB9CiAgXQp9"""
    )
    public String getBom() {
        return bom;
    }

}
