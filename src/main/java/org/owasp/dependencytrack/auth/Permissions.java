/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.auth;

/**
 * Defines permissions specific to Dependency-Track.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public enum Permissions {

    BOM_UPLOAD("Allows the ability to upload CycloneDX and SPDX Bill-of-Material (BOM) documents"),
    SCAN_UPLOAD("Allows the ability to upload Dependency-Check XML reports"),
    VIEW_PORTFOLIO("Provides the ability to view the portfolio of projects, components, dependencies, and licenses"),
    PORTFOLIO_MANAGEMENT("Allows the creation, modification, and deletion of data in the portfolio"),
    VULNERABILITY_ANALYSIS("Provides the ability to make analysis decisions on vulnerabilities affecting projects in the portfolio"),
    ACCESS_MANAGEMENT("Allows the management of users, teams, and API keys");

    private final String description;

    Permissions(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static class Constants {
        public static final String BOM_UPLOAD = "BOM_UPLOAD";
        public static final String SCAN_UPLOAD = "SCAN_UPLOAD";
        public static final String VIEW_PORTFOLIO = "VIEW_PORTFOLIO";
        public static final String PORTFOLIO_MANAGEMENT = "PORTFOLIO_MANAGEMENT";
        public static final String VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS";
        public static final String ACCESS_MANAGEMENT = "ACCESS_MANAGEMENT";
    }

}
