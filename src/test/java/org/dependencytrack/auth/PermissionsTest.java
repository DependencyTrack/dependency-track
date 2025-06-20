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
package org.dependencytrack.auth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.BOM_UPLOAD;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_VIOLATION_ANALYSIS;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.PROJECT_CREATION_UPLOAD;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION;
import static org.dependencytrack.auth.Permissions.Constants.TAG_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_POLICY_VIOLATION;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_PORTFOLIO;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_VULNERABILITY;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_BADGES;
class PermissionsTest {

    @Test
    void testPermissionEnums() {
        Assertions.assertEquals(14, Permissions.values().length);
        Assertions.assertEquals("BOM_UPLOAD", Permissions.BOM_UPLOAD.name());
        Assertions.assertEquals("VIEW_PORTFOLIO", Permissions.VIEW_PORTFOLIO.name());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT", Permissions.PORTFOLIO_MANAGEMENT.name());
        Assertions.assertEquals("VIEW_VULNERABILITY", Permissions.VIEW_VULNERABILITY.name());
        Assertions.assertEquals("VULNERABILITY_ANALYSIS", Permissions.VULNERABILITY_ANALYSIS.name());
        Assertions.assertEquals("VIEW_POLICY_VIOLATION", Permissions.VIEW_POLICY_VIOLATION.name());
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT", Permissions.VULNERABILITY_MANAGEMENT.name());
        Assertions.assertEquals("POLICY_VIOLATION_ANALYSIS", Permissions.POLICY_VIOLATION_ANALYSIS.name());
        Assertions.assertEquals("ACCESS_MANAGEMENT", Permissions.ACCESS_MANAGEMENT.name());
        Assertions.assertEquals("SYSTEM_CONFIGURATION", Permissions.SYSTEM_CONFIGURATION.name());
        Assertions.assertEquals("PROJECT_CREATION_UPLOAD", Permissions.PROJECT_CREATION_UPLOAD.name());
        Assertions.assertEquals("POLICY_MANAGEMENT", Permissions.POLICY_MANAGEMENT.name());
        Assertions.assertEquals("TAG_MANAGEMENT", Permissions.TAG_MANAGEMENT.name());
        Assertions.assertEquals("VIEW_BADGES", Permissions.VIEW_BADGES.name());
    }

    @Test
    void testPermissionConstants() {
        Assertions.assertEquals("BOM_UPLOAD", BOM_UPLOAD);
        Assertions.assertEquals("VIEW_PORTFOLIO", VIEW_PORTFOLIO);
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT", PORTFOLIO_MANAGEMENT);
        Assertions.assertEquals("VIEW_VULNERABILITY", VIEW_VULNERABILITY);
        Assertions.assertEquals("VULNERABILITY_ANALYSIS", VULNERABILITY_ANALYSIS);
        Assertions.assertEquals("VIEW_POLICY_VIOLATION", VIEW_POLICY_VIOLATION);
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT", VULNERABILITY_MANAGEMENT);
        Assertions.assertEquals("POLICY_VIOLATION_ANALYSIS", POLICY_VIOLATION_ANALYSIS);
        Assertions.assertEquals("ACCESS_MANAGEMENT", ACCESS_MANAGEMENT);
        Assertions.assertEquals("SYSTEM_CONFIGURATION", SYSTEM_CONFIGURATION);
        Assertions.assertEquals("PROJECT_CREATION_UPLOAD", PROJECT_CREATION_UPLOAD);
        Assertions.assertEquals("POLICY_MANAGEMENT", POLICY_MANAGEMENT);
        Assertions.assertEquals("TAG_MANAGEMENT", TAG_MANAGEMENT);
        Assertions.assertEquals("VIEW_BADGES", VIEW_BADGES);
    }
}
