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
package org.dependencytrack.model.scheduled;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;
import org.dependencytrack.model.Finding;

import alpine.common.logging.Logger;

public class DetailInfo {
    private static final Logger LOGGER = Logger.getLogger(DetailInfo.class);

    private final String componentName;
    private final String componentVersion;
    private final String componentGroup;
    private final String vulnerabilityId;
    private final String vulnerabilitySeverity;
    private final String analyzer;
    private Date attributedOn;
    private final String analysisState;
    private final Boolean suppressed;

    public DetailInfo(Finding finding) {
        this.componentName = (String) finding.getComponent().get("name");
        this.componentVersion = (String) finding.getComponent().get("version");
        this.componentGroup = (String) finding.getComponent().get("group");
        this.vulnerabilityId = (String) finding.getVulnerability().get("vulnId");
        this.vulnerabilitySeverity = (String) finding.getVulnerability().get("severity");
        this.analyzer = (String) finding.getAttribution().get("analyzerIdentity");
        try {
            this.attributedOn = DateFormat.getDateTimeInstance().parse((String) finding.getAttribution().get("attributedOn"));
        } catch (ParseException e) {
            this.attributedOn = null;
            LOGGER.error("An error occurred while parsing the attributedOn date for component" + this.componentName);
        }
        this.analysisState = (String) finding.getAnalysis().get("state");
        this.suppressed = (Boolean) finding.getAnalysis().get("isSuppressed");
    }

    public String getComponentName() {
        return componentName;
    }

    public String getComponentVersion() {
        return componentVersion;
    }

    public String getComponentGroup() {
        return componentGroup;
    }

    public String getVulnerabilityId() {
        return vulnerabilityId;
    }

    public String getVulnerabilitySeverity() {
        return vulnerabilitySeverity;
    }

    public String getAnalyzer() {
        return analyzer;
    }

    public Date getAttributedOn() {
        return attributedOn;
    }

    public String getAnalysisState() {
        return analysisState;
    }

    public Boolean getSuppressed() {
        return suppressed;
    }
}
