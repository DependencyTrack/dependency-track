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
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

/**
 * Defines a custom request object used when updating analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class AnalysisRequest {

    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The project must be a valid 36 character UUID")
    private final String project;

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The component must be a valid 36 character UUID")
    private final String component;

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The vulnerability must be a valid 36 character UUID")
    private final String vulnerability;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The comment may only contain printable characters")
    private final String comment;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The comment may only contain printable characters")
    private final String analysisDetails;

    private final AnalysisState analysisState;

    private final AnalysisJustification analysisJustification;

    private final AnalysisResponse analysisResponse;

    private final Boolean suppressed; // Optional. If not specified, we do not want to set value to false, thus using Boolean object rather than primitive.

    @JsonCreator
    public AnalysisRequest(@JsonProperty(value = "project") String project,
                           @JsonProperty(value = "component", required = true) String component,
                           @JsonProperty(value = "vulnerability", required = true) String vulnerability,
                           @JsonProperty(value = "analysisState") AnalysisState analysisState,
                           @JsonProperty(value = "analysisJustification") AnalysisJustification analysisJustification,
                           @JsonProperty(value = "analysisResponse") AnalysisResponse analysisResponse,
                           @JsonProperty(value = "analysisDetails") String analysisDetails,
                           @JsonProperty(value = "comment") String comment,
                           @JsonProperty(value = "isSuppressed") Boolean suppressed) {
        this.project = project;
        this.component = component;
        this.vulnerability = vulnerability;
        this.analysisState = analysisState;
        this.analysisJustification = analysisJustification;
        this.analysisResponse = analysisResponse;
        this.analysisDetails = analysisDetails;
        this.comment = comment;
        this.suppressed = suppressed;
    }

    public String getProject() {
        return project;
    }

    public String getComponent() {
        return component;
    }

    public String getVulnerability() {
        return vulnerability;
    }

    public AnalysisState getAnalysisState() {
        if (analysisState == null) {
            return AnalysisState.NOT_SET;
        } else {
            return analysisState;
        }
    }

    public AnalysisJustification getAnalysisJustification() {
        if (analysisJustification == null) {
            return AnalysisJustification.NOT_SET;
        } else {
            return analysisJustification;
        }
    }

    public AnalysisResponse getAnalysisResponse() {
        if (analysisResponse == null) {
            return AnalysisResponse.NOT_SET;
        } else {
            return analysisResponse;
        }
    }

    public String getAnalysisDetails() {
        return analysisDetails;
    }

    public String getComment() {
        return comment;
    }

    public Boolean isSuppressed() {
        return suppressed;
    }
}
