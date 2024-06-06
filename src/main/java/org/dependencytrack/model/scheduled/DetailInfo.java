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

import java.util.Date;
import org.dependencytrack.model.Finding;
import org.dependencytrack.util.DateUtil;

import alpine.common.logging.Logger;

public class DetailInfo {
    private static final Logger LOGGER = Logger.getLogger(DetailInfo.class);

    private final String componentUuid;
    private final String componentName;
    private final String componentVersion;
    private final String componentGroup;
    private final String vulnerabilitySource;
    private final String vulnerabilityId;
    private final String vulnerabilitySeverity;
    private final String analyzer;
    private final String attributionReferenceUrl;
    private final String attributedOn;
    private final String analysisState;
    private final String suppressed;

    public DetailInfo(Finding finding) {
        this.componentUuid = getValueOrUnknownIfNull(finding.getComponent().get("uuid"));
        this.componentName = getValueOrUnknownIfNull(finding.getComponent().get("name"));
        this.componentVersion = getValueOrUnknownIfNull(finding.getComponent().get("version"));
        this.componentGroup = getValueOrUnknownIfNull(finding.getComponent().get("group"));
        this.vulnerabilitySource = getValueOrUnknownIfNull(finding.getVulnerability().get("source"));
        this.vulnerabilityId = getValueOrUnknownIfNull(finding.getVulnerability().get("vulnId"));
        this.vulnerabilitySeverity = getValueOrUnknownIfNull(finding.getVulnerability().get("severity"));
        this.analyzer = getValueOrUnknownIfNull(finding.getAttribution().get("analyzerIdentity"));
        this.attributionReferenceUrl = getValueOrUnknownIfNull(finding.getAttribution().get("referenceUrl"));
        this.attributedOn = getDateOrUnknownIfNull((Date) finding.getAttribution().get("attributedOn"));
        this.analysisState = getValueOrUnknownIfNull(finding.getAnalysis().get("state"));
        this.suppressed = finding.getAnalysis().get("isSuppressed") instanceof Boolean
                ? (Boolean) finding.getAnalysis().get("isSuppressed") ? "Yes" : "No"
                : "No";
    }

    private static String getValueOrUnknownIfNull(Object value) {
        return value == null ? "" : value.toString();
    }

    private static String getDateOrUnknownIfNull(Date date) {
        return date == null ? "Unknown" : DateUtil.toISO8601(date);
    }

    public String getComponentUuid() {
        return componentUuid;
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

    public String getVulnerabilitySource() {
        return vulnerabilitySource;
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

    public String getAttributionReferenceUrl() {
        return attributionReferenceUrl;
    }

    public String getAttributedOn() {
        return attributedOn;
    }

    public String getAnalysisState() {
        return analysisState;
    }

    public String getSuppressed() {
        return suppressed;
    }
}
