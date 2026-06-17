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
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.BOM_UPLOAD;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_VIOLATION_ANALYSIS;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.PROJECT_CREATION_UPLOAD;
import static org.dependencytrack.auth.Permissions.Constants.SECRET_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.SECRET_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.SECRET_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.SECRET_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_READ;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.TAG_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.TAG_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_POLICY_VIOLATION;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_PORTFOLIO;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_VULNERABILITY;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS_READ;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE;

public class PermissionsTest {

    @Test
    public void testPermissionEnums() {
        Assertions.assertEquals(42, Permissions.values().length);
        Assertions.assertEquals("BOM_UPLOAD", Permissions.BOM_UPLOAD.name());
        Assertions.assertEquals("VIEW_PORTFOLIO", Permissions.VIEW_PORTFOLIO.name());
        Assertions.assertEquals("PORTFOLIO_ACCESS_CONTROL_BYPASS", Permissions.PORTFOLIO_ACCESS_CONTROL_BYPASS.name());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT", Permissions.PORTFOLIO_MANAGEMENT.name());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_CREATE", Permissions.PORTFOLIO_MANAGEMENT_CREATE.name());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_READ", Permissions.PORTFOLIO_MANAGEMENT_READ.name());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_UPDATE", Permissions.PORTFOLIO_MANAGEMENT_UPDATE.name());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_DELETE", Permissions.PORTFOLIO_MANAGEMENT_DELETE.name());
        Assertions.assertEquals("VIEW_VULNERABILITY", Permissions.VIEW_VULNERABILITY.name());
        Assertions.assertEquals("VULNERABILITY_ANALYSIS", Permissions.VULNERABILITY_ANALYSIS.name());
        Assertions.assertEquals("VULNERABILITY_ANALYSIS_CREATE", Permissions.VULNERABILITY_ANALYSIS_CREATE.name());
        Assertions.assertEquals("VULNERABILITY_ANALYSIS_READ", Permissions.VULNERABILITY_ANALYSIS_READ.name());
        Assertions.assertEquals("VULNERABILITY_ANALYSIS_UPDATE", Permissions.VULNERABILITY_ANALYSIS_UPDATE.name());
        Assertions.assertEquals("VIEW_POLICY_VIOLATION", Permissions.VIEW_POLICY_VIOLATION.name());
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT", Permissions.VULNERABILITY_MANAGEMENT.name());
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_CREATE", Permissions.VULNERABILITY_MANAGEMENT_CREATE.name());
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_READ", Permissions.VULNERABILITY_MANAGEMENT_READ.name());
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_UPDATE", Permissions.VULNERABILITY_MANAGEMENT_UPDATE.name());
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_DELETE", Permissions.VULNERABILITY_MANAGEMENT_DELETE.name());
        Assertions.assertEquals("POLICY_VIOLATION_ANALYSIS", Permissions.POLICY_VIOLATION_ANALYSIS.name());
        Assertions.assertEquals("ACCESS_MANAGEMENT", Permissions.ACCESS_MANAGEMENT.name());
        Assertions.assertEquals("ACCESS_MANAGEMENT_CREATE", Permissions.ACCESS_MANAGEMENT_CREATE.name());
        Assertions.assertEquals("ACCESS_MANAGEMENT_READ", Permissions.ACCESS_MANAGEMENT_READ.name());
        Assertions.assertEquals("ACCESS_MANAGEMENT_UPDATE", Permissions.ACCESS_MANAGEMENT_UPDATE.name());
        Assertions.assertEquals("ACCESS_MANAGEMENT_DELETE", Permissions.ACCESS_MANAGEMENT_DELETE.name());
        Assertions.assertEquals("SECRET_MANAGEMENT", Permissions.SECRET_MANAGEMENT.name());
        Assertions.assertEquals("SECRET_MANAGEMENT_CREATE", Permissions.SECRET_MANAGEMENT_CREATE.name());
        Assertions.assertEquals("SECRET_MANAGEMENT_UPDATE", Permissions.SECRET_MANAGEMENT_UPDATE.name());
        Assertions.assertEquals("SECRET_MANAGEMENT_DELETE", Permissions.SECRET_MANAGEMENT_DELETE.name());
        Assertions.assertEquals("SYSTEM_CONFIGURATION", Permissions.SYSTEM_CONFIGURATION.name());
        Assertions.assertEquals("SYSTEM_CONFIGURATION_CREATE", Permissions.SYSTEM_CONFIGURATION_CREATE.name());
        Assertions.assertEquals("SYSTEM_CONFIGURATION_READ", Permissions.SYSTEM_CONFIGURATION_READ.name());
        Assertions.assertEquals("SYSTEM_CONFIGURATION_UPDATE", Permissions.SYSTEM_CONFIGURATION_UPDATE.name());
        Assertions.assertEquals("SYSTEM_CONFIGURATION_DELETE", Permissions.SYSTEM_CONFIGURATION_DELETE.name());
        Assertions.assertEquals("PROJECT_CREATION_UPLOAD", Permissions.PROJECT_CREATION_UPLOAD.name());
        Assertions.assertEquals("POLICY_MANAGEMENT", Permissions.POLICY_MANAGEMENT.name());
        Assertions.assertEquals("POLICY_MANAGEMENT_CREATE", Permissions.POLICY_MANAGEMENT_CREATE.name());
        Assertions.assertEquals("POLICY_MANAGEMENT_READ", Permissions.POLICY_MANAGEMENT_READ.name());
        Assertions.assertEquals("POLICY_MANAGEMENT_UPDATE", Permissions.POLICY_MANAGEMENT_UPDATE.name());
        Assertions.assertEquals("POLICY_MANAGEMENT_DELETE", Permissions.POLICY_MANAGEMENT_DELETE.name());
        Assertions.assertEquals("TAG_MANAGEMENT", Permissions.TAG_MANAGEMENT.name());
        Assertions.assertEquals("TAG_MANAGEMENT_DELETE", Permissions.TAG_MANAGEMENT_DELETE.name());
    }

    @Test
    public void testPermissionConstants() {
        Assertions.assertEquals("BOM_UPLOAD", BOM_UPLOAD);
        Assertions.assertEquals("VIEW_PORTFOLIO", VIEW_PORTFOLIO);
        Assertions.assertEquals("PORTFOLIO_ACCESS_CONTROL_BYPASS", PORTFOLIO_ACCESS_CONTROL_BYPASS);
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT", PORTFOLIO_MANAGEMENT);
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_CREATE", PORTFOLIO_MANAGEMENT_CREATE);
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_READ", PORTFOLIO_MANAGEMENT_READ);
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_UPDATE", PORTFOLIO_MANAGEMENT_UPDATE);
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT_DELETE", PORTFOLIO_MANAGEMENT_DELETE);
        Assertions.assertEquals("VIEW_VULNERABILITY", VIEW_VULNERABILITY);
        Assertions.assertEquals("VULNERABILITY_ANALYSIS", VULNERABILITY_ANALYSIS);
        Assertions.assertEquals("VULNERABILITY_ANALYSIS_CREATE", VULNERABILITY_ANALYSIS_CREATE);
        Assertions.assertEquals("VULNERABILITY_ANALYSIS_READ", VULNERABILITY_ANALYSIS_READ);
        Assertions.assertEquals("VULNERABILITY_ANALYSIS_UPDATE", VULNERABILITY_ANALYSIS_UPDATE);
        Assertions.assertEquals("VIEW_POLICY_VIOLATION", VIEW_POLICY_VIOLATION);
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT", VULNERABILITY_MANAGEMENT);
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_CREATE", VULNERABILITY_MANAGEMENT_CREATE);
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_READ", VULNERABILITY_MANAGEMENT_READ);
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_UPDATE", VULNERABILITY_MANAGEMENT_UPDATE);
        Assertions.assertEquals("VULNERABILITY_MANAGEMENT_DELETE", VULNERABILITY_MANAGEMENT_DELETE);
        Assertions.assertEquals("POLICY_VIOLATION_ANALYSIS", POLICY_VIOLATION_ANALYSIS);
        Assertions.assertEquals("ACCESS_MANAGEMENT", ACCESS_MANAGEMENT);
        Assertions.assertEquals("ACCESS_MANAGEMENT_CREATE", ACCESS_MANAGEMENT_CREATE);
        Assertions.assertEquals("ACCESS_MANAGEMENT_READ", ACCESS_MANAGEMENT_READ);
        Assertions.assertEquals("ACCESS_MANAGEMENT_UPDATE", ACCESS_MANAGEMENT_UPDATE);
        Assertions.assertEquals("ACCESS_MANAGEMENT_DELETE", ACCESS_MANAGEMENT_DELETE);
        Assertions.assertEquals("SECRET_MANAGEMENT", SECRET_MANAGEMENT);
        Assertions.assertEquals("SECRET_MANAGEMENT_CREATE", SECRET_MANAGEMENT_CREATE);
        Assertions.assertEquals("SECRET_MANAGEMENT_UPDATE", SECRET_MANAGEMENT_UPDATE);
        Assertions.assertEquals("SECRET_MANAGEMENT_DELETE", SECRET_MANAGEMENT_DELETE);
        Assertions.assertEquals("SYSTEM_CONFIGURATION", SYSTEM_CONFIGURATION);
        Assertions.assertEquals("SYSTEM_CONFIGURATION_CREATE", SYSTEM_CONFIGURATION_CREATE);
        Assertions.assertEquals("SYSTEM_CONFIGURATION_READ", SYSTEM_CONFIGURATION_READ);
        Assertions.assertEquals("SYSTEM_CONFIGURATION_UPDATE", SYSTEM_CONFIGURATION_UPDATE);
        Assertions.assertEquals("SYSTEM_CONFIGURATION_DELETE", SYSTEM_CONFIGURATION_DELETE);
        Assertions.assertEquals("PROJECT_CREATION_UPLOAD", PROJECT_CREATION_UPLOAD);
        Assertions.assertEquals("POLICY_MANAGEMENT", POLICY_MANAGEMENT);
        Assertions.assertEquals("POLICY_MANAGEMENT_CREATE", POLICY_MANAGEMENT_CREATE);
        Assertions.assertEquals("POLICY_MANAGEMENT_READ", POLICY_MANAGEMENT_READ);
        Assertions.assertEquals("POLICY_MANAGEMENT_UPDATE", POLICY_MANAGEMENT_UPDATE);
        Assertions.assertEquals("POLICY_MANAGEMENT_DELETE", POLICY_MANAGEMENT_DELETE);
        Assertions.assertEquals("TAG_MANAGEMENT", TAG_MANAGEMENT);
        Assertions.assertEquals("TAG_MANAGEMENT_DELETE", TAG_MANAGEMENT_DELETE);
    }
}
