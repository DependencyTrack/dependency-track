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
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import java.io.Serializable;

/**
 * Model class for tracking external references.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExternalReference implements Serializable {

    private static final long serialVersionUID = -5885851731192037664L;

    private org.cyclonedx.model.ExternalReference.Type type;

    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String url;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The comment may only contain printable characters")
    private String comment;

    public org.cyclonedx.model.ExternalReference.Type getType() {
        return type;
    }

    public void setType(org.cyclonedx.model.ExternalReference.Type type) {
        this.type = type;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }
}
