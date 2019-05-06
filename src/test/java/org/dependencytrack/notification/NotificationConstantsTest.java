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
package org.dependencytrack.notification;

import org.junit.Assert;
import org.junit.Test;

public class NotificationConstantsTest {

    @Test
    public void testConstants() {
        Assert.assertEquals("Notification Test", NotificationConstants.Title.NOTIFICATION_TEST);
        Assert.assertEquals("NVD Mirroring", NotificationConstants.Title.NVD_MIRROR);
        Assert.assertEquals("NPM Advisory Mirroring", NotificationConstants.Title.NPM_ADVISORY_MIRROR);
        Assert.assertEquals("VulnDB Mirroring", NotificationConstants.Title.VULNDB_MIRROR);
        Assert.assertEquals("Component Indexing Service", NotificationConstants.Title.COMPONENT_INDEXER);
        Assert.assertEquals("License Indexing Service", NotificationConstants.Title.LICENSE_INDEXER);
        Assert.assertEquals("Project Indexing Service", NotificationConstants.Title.PROJECT_INDEXER);
        Assert.assertEquals("Vulnerability Indexing Service", NotificationConstants.Title.VULNERABILITY_INDEXER);
        Assert.assertEquals("Core Indexing Services", NotificationConstants.Title.CORE_INDEXING_SERVICES);
        Assert.assertEquals("File System Error", NotificationConstants.Title.FILE_SYSTEM_ERROR);
        Assert.assertEquals("Repository Error", NotificationConstants.Title.REPO_ERROR);
        Assert.assertEquals("Integration Error", NotificationConstants.Title.INTEGRATION_ERROR);
        Assert.assertEquals("New Vulnerability Identified", NotificationConstants.Title.NEW_VULNERABILITY);
        Assert.assertEquals("Vulnerable Dependency Introduced", NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY);
        Assert.assertEquals("Analysis Decision: Exploitable", NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE);
        Assert.assertEquals("Analysis Decision: In Triage", NotificationConstants.Title.ANALYSIS_DECISION_IN_TRIAGE);
        Assert.assertEquals("Analysis Decision: False Positive", NotificationConstants.Title.ANALYSIS_DECISION_FALSE_POSITIVE);
        Assert.assertEquals("Analysis Decision: Not Affected", NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED);
        Assert.assertEquals("Analysis Decision: Marking Finding as NOT SET", NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET);
        Assert.assertEquals("Analysis Decision: Finding Suppressed", NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED);
        Assert.assertEquals("Analysis Decision: Finding UnSuppressed", NotificationConstants.Title.ANALYSIS_DECISION_UNSUPPRESSED);
    }
}
