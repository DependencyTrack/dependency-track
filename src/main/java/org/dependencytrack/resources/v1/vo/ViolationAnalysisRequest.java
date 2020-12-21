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
package org.dependencytrack.resources.v1.vo;

import alpine.json.TrimmedStringDeserializer;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.dependencytrack.model.ViolationAnalysisState;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

/**
 * Defines a custom request object used when updating violation analysis decisions.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class ViolationAnalysisRequest {

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The component must be a valid 36 character UUID")
    private final String component;

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The policy violation must be a valid 36 character UUID")
    private final String policyViolation;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The comment may only contain printable characters")
    private final String comment;

    private final ViolationAnalysisState analysisState;

    private final Boolean suppressed; // Optional. If not specified, we do not want to set value to false, thus using Boolean object rather than primitive.

    @JsonCreator
    public ViolationAnalysisRequest(@JsonProperty(value = "component", required = true) String component,
                           @JsonProperty(value = "policyViolation", required = true) String policyViolation,
                           @JsonProperty(value = "analysisState") ViolationAnalysisState analysisState,
                           @JsonProperty(value = "comment") String comment,
                           @JsonProperty(value = "isSuppressed") Boolean suppressed) {
        this.component = component;
        this.policyViolation = policyViolation;
        this.analysisState = analysisState;
        this.comment = comment;
        this.suppressed = suppressed;
    }

    public String getComponent() {
        return component;
    }

    public String getPolicyViolation() {
        return policyViolation;
    }

    public ViolationAnalysisState getAnalysisState() {
        if (analysisState == null) {
            return ViolationAnalysisState.NOT_SET;
        } else {
            return analysisState;
        }
    }

    public String getComment() {
        return comment;
    }

    public Boolean isSuppressed() {
        return suppressed;
    }
}
