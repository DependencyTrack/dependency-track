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
package org.dependencytrack.services;

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;

import java.util.ArrayList;
import java.util.List;

/**
 * Technical object that encapsulates analysis info for use by the AnalysisService.
 */
public class AnalysisDescription {
    protected AnalysisState analysisState;
    protected AnalysisJustification analysisJustification;
    protected List<AnalysisResponse> analysisResponses;
    protected String analysisDetails;
    protected String comment;
    protected Boolean isSuppressed;

    public AnalysisState getAnalysisState() {
        return analysisState;
    }

    protected void setAnalysisState(AnalysisState analysisState) {
        this.analysisState = analysisState;
    }

    public AnalysisJustification getAnalysisJustification() {
        return analysisJustification;
    }

    protected void setAnalysisJustification(AnalysisJustification analysisJustification) {
        this.analysisJustification = analysisJustification;
    }

    public List<AnalysisResponse> getAnalysisResponses() {
        return analysisResponses;
    }

    protected void addAnalysisResponse(AnalysisResponse analysisResponse) {
        if (this.analysisResponses == null) {
            this.analysisResponses = new ArrayList<>();
        }
        this.analysisResponses.add(analysisResponse);
    }

    public String getAnalysisDetails() {
        return analysisDetails;
    }

    protected void setAnalysisDetails(String analysisDetails) {
        this.analysisDetails = analysisDetails;
    }

    protected void suppressed(Boolean isSuppressed) {
        this.isSuppressed = isSuppressed;
    }

    public Boolean isSuppressed() {
        return isSuppressed;
    }

    public String getComment() {
        return comment;
    }

    protected void setComment(String comment) {
        this.comment = comment;
    }
}
