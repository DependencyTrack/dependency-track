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
package org.dependencytrack.parser.composer.model;

//TODO fix file

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;

public class ComposerSecurityAdvisory {

    private String advisoryId;
    private String packageName;
    private String remoteId;
    private String title;
    private String link;
    private String cve;
    private String affectedVersionsCve;
    private String source;
    private ZonedDateTime reportedAt;
    private String composerRepository;
    private String severity;
    private List<Pair<String, String>> sources;

    public String getAdvisoryId() {
        return advisoryId;
    }

    public void setAdvisoryId(String advisoryId) {
        this.advisoryId = advisoryId;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getRemoteId() {
        return remoteId;
    }

    public void setRemoteId(String remoteId) {
        this.remoteId = remoteId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getCve() {
        return cve;
    }

    public void setCve(String cve) {
        this.cve = cve;
    }

    public String getAffectedVersionsCve() {
        return affectedVersionsCve;
    }

    public void setAffectedVersionsCve(String affectedVersionsCve) {
        this.affectedVersionsCve = affectedVersionsCve;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public ZonedDateTime getReportedAt() {
        return reportedAt;
    }

    public void setReportedAt(ZonedDateTime reportedAt) {
        this.reportedAt = reportedAt;
    }

    public String getComposerRepository() {
        return composerRepository;
    }

    public void setComposerRepository(String composerRepository) {
        this.composerRepository = composerRepository;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public List<Pair<String, String>> getSources() {
        return sources;
    }

    public void setSources(List<Pair<String, String>> sources) {
        this.sources = sources;
    }

    public void addSource(Pair<String, String> source) {
       if (this.sources == null) {
            this.sources = new ArrayList<>();
        }
        this.sources.add(source);
    }

}
