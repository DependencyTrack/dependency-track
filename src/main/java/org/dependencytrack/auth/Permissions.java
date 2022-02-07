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
package org.dependencytrack.auth;

/**
 * Defines permissions specific to Dependency-Track.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public enum Permissions {

    BOM_UPLOAD("Allows the ability to upload CycloneDX Software Bill of Materials (SBOM)"),
    VIEW_PORTFOLIO("Provides the ability to view the portfolio of projects, components, and licenses"),
    PORTFOLIO_MANAGEMENT("Allows the creation, modification, and deletion of data in the portfolio"),
    VIEW_VULNERABILITY("Provides the ability to view the vulnerabilities projects are affected by"),
    VULNERABILITY_ANALYSIS("Provides the ability to make analysis decisions on vulnerabilities"),
    POLICY_VIOLATION_ANALYSIS("Provides the ability to make analysis decisions on policy violations"),
    ACCESS_MANAGEMENT("Allows the management of users, teams, and API keys"),
    SYSTEM_CONFIGURATION("Allows the configuration of the system including notifications, repositories, and email settings"),
    PROJECT_CREATION_UPLOAD("Provides the ability to optionally create project (if non-existent) on BOM or scan upload"),
    POLICY_MANAGEMENT("Allows the creation, modification, and deletion of policy");

    private final String description;

    Permissions(final String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static class Constants {
        public static final String BOM_UPLOAD = "BOM_UPLOAD";
        public static final String VIEW_PORTFOLIO = "VIEW_PORTFOLIO";
        public static final String PORTFOLIO_MANAGEMENT = "PORTFOLIO_MANAGEMENT";
        public static final String VIEW_VULNERABILITY = "VIEW_VULNERABILITY";
        public static final String VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS";
        public static final String POLICY_VIOLATION_ANALYSIS = "POLICY_VIOLATION_ANALYSIS";
        public static final String ACCESS_MANAGEMENT = "ACCESS_MANAGEMENT";
        public static final String SYSTEM_CONFIGURATION = "SYSTEM_CONFIGURATION";
        public static final String PROJECT_CREATION_UPLOAD = "PROJECT_CREATION_UPLOAD";
        public static final String POLICY_MANAGEMENT = "POLICY_MANAGEMENT";
    }

}
