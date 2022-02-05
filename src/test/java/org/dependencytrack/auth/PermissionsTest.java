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

import org.junit.Assert;
import org.junit.Test;

import static org.dependencytrack.auth.Permissions.Constants.*;

public class PermissionsTest {

    @Test
    public void testPermissionEnums() {
        Assert.assertEquals(10, Permissions.values().length);
        Assert.assertEquals("BOM_UPLOAD", Permissions.BOM_UPLOAD.name());
        Assert.assertEquals("VIEW_PORTFOLIO", Permissions.VIEW_PORTFOLIO.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", Permissions.PORTFOLIO_MANAGEMENT.name());
        Assert.assertEquals("VIEW_VULNERABILITY", Permissions.VIEW_VULNERABILITY.name());
        Assert.assertEquals("VULNERABILITY_ANALYSIS", Permissions.VULNERABILITY_ANALYSIS.name());
        Assert.assertEquals("POLICY_VIOLATION_ANALYSIS", Permissions.POLICY_VIOLATION_ANALYSIS.name());
        Assert.assertEquals("ACCESS_MANAGEMENT", Permissions.ACCESS_MANAGEMENT.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION", Permissions.SYSTEM_CONFIGURATION.name());
        Assert.assertEquals("PROJECT_CREATION_UPLOAD", Permissions.PROJECT_CREATION_UPLOAD.name());
        Assert.assertEquals("POLICY_MANAGEMENT", Permissions.POLICY_MANAGEMENT.name());
    }

    @Test
    public void testPermissionConstants() {
        Assert.assertEquals("BOM_UPLOAD", BOM_UPLOAD);
        Assert.assertEquals("VIEW_PORTFOLIO", VIEW_PORTFOLIO);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", PORTFOLIO_MANAGEMENT);
        Assert.assertEquals("VIEW_VULNERABILITY", VIEW_VULNERABILITY);
        Assert.assertEquals("VULNERABILITY_ANALYSIS", VULNERABILITY_ANALYSIS);
        Assert.assertEquals("POLICY_VIOLATION_ANALYSIS", POLICY_VIOLATION_ANALYSIS);
        Assert.assertEquals("ACCESS_MANAGEMENT", ACCESS_MANAGEMENT);
        Assert.assertEquals("SYSTEM_CONFIGURATION", SYSTEM_CONFIGURATION);
        Assert.assertEquals("PROJECT_CREATION_UPLOAD", PROJECT_CREATION_UPLOAD);
        Assert.assertEquals("POLICY_MANAGEMENT", POLICY_MANAGEMENT);
    }
}
