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
package org.dependencytrack.parser.ossindex.model;

import java.util.ArrayList;
import java.util.List;

/**
 * The response from Sonatype OSS Index will respond with 0 or more ComponentReports. This
 * class defines the ComponentReport objects returned.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
public class ComponentReport {

    private String coordinates;
    private String description;
    private String reference;
    private final List<ComponentReportVulnerability> vulnerabilities = new ArrayList<>();

    public String getCoordinates() {
        return coordinates;
    }

    public void setCoordinates(final String coordinates) {
        this.coordinates = coordinates;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }

    public String getReference() {
        return reference;
    }

    public void setReference(final String reference) {
        this.reference = reference;
    }

    public List<ComponentReportVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void addVulnerability(final ComponentReportVulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }
}
