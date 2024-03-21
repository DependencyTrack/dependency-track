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

public class AnalysisDescriptionBuilder {
    private AnalysisDescription analysis;

    public AnalysisDescriptionBuilder withDetails(String details) {
        get().setAnalysisDetails(details);
        return this;
    }

    public AnalysisDescriptionBuilder withJustification(AnalysisJustification justification) {
        get().setAnalysisJustification(justification);
        return this;
    }

    public AnalysisDescriptionBuilder withState(AnalysisState state) {
        get().setAnalysisState(state);
        return this;
    }

    public AnalysisDescriptionBuilder withComment(String comment) {
        get().setComment(comment);
        return this;
    }

    public AnalysisDescriptionBuilder withResponse(AnalysisResponse response) {
        get().addAnalysisResponse(response);
        return this;
    }

    public AnalysisDescriptionBuilder withSuppression(Boolean isSuppressed) {
        get().suppressed(isSuppressed);
        return this;
    }

    public AnalysisDescription build() {
        return get();
    }

    private AnalysisDescription get() {
        if (this.analysis == null) {
            this.analysis = new AnalysisDescription();
        }
        return analysis;
    }
}
