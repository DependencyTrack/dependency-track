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

import java.util.ArrayList;
import java.util.List;

public class NotificationAlias {

    private Vulnerability.Source source;
    private String vulnId;
    private List<Vulnerability.Source> reportedBy;

    public NotificationAlias(Vulnerability.Source source, String vulnId, List<Vulnerability.Source> reportedBy) {
        this.setSource(source);
        this.setVulnId(vulnId);
        this.setReportedBy(reportedBy);
    }

    public NotificationAlias() {
    }

    public Vulnerability.Source getSource() {
        return source;
    }

    public void setSource(Vulnerability.Source source) {
        this.source = source;
    }

    public String getVulnId() {
        return vulnId;
    }

    public void setVulnId(String vulnId) {
        this.vulnId = vulnId;
    }

    public List<Vulnerability.Source> getReportedBy() {
        return reportedBy;
    }

    public void setReportedBy(List<Vulnerability.Source> reportedBy) {
        this.reportedBy = reportedBy;
    }

    public void addReportedBy(Vulnerability.Source reportedBy) {
        if (reportedBy == null) {
            return;
        }
        if (this.reportedBy == null) {
            this.reportedBy = new ArrayList<>();
        }
        this.reportedBy.add(reportedBy);
    }
}
