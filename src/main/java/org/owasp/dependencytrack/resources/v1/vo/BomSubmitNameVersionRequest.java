/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.resources.v1.vo;

import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

/**
 * Defines a custom request object used when uploading Dependency-Check bill-of-material (bom) documents.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class BomSubmitNameVersionRequest {

    @NotNull
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The project name may only contain printable characters")
    private final String projectName;

    @NotNull
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The project version may only contain printable characters")
    private final String projectVersion;

    @NotNull
    @Pattern(regexp = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", message = "BoM must be Base64 encoded")
    private final String bom;

    private final boolean autoCreate;

    @JsonCreator
    public BomSubmitNameVersionRequest(@JsonProperty(value = "projectName", required = true) String projectName,
                                       @JsonProperty(value = "projectVersion", required = true) String projectVersion,
                                       @JsonProperty(value = "autoCreate", required = false) boolean autoCreate,
                                       @JsonProperty(value = "bom", required = true) String bom) {
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.autoCreate = autoCreate;
        this.bom = bom;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public boolean isAutoCreate() {
        return autoCreate;
    }

    public String getBom() {
        return bom;
    }

}
