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
package org.dependencytrack.notification;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class NotificationConstantsTest {

    @Test
    void testConstants() {
        Assertions.assertEquals("Notification Test", NotificationConstants.Title.NOTIFICATION_TEST);
        Assertions.assertEquals("NVD Mirroring", NotificationConstants.Title.NVD_MIRROR);
        Assertions.assertEquals("NPM Advisory Mirroring", NotificationConstants.Title.NPM_ADVISORY_MIRROR);
        Assertions.assertEquals("VulnDB Mirroring", NotificationConstants.Title.VULNDB_MIRROR);
        Assertions.assertEquals("Component Indexing Service", NotificationConstants.Title.COMPONENT_INDEXER);
        Assertions.assertEquals("License Indexing Service", NotificationConstants.Title.LICENSE_INDEXER);
        Assertions.assertEquals("Project Indexing Service", NotificationConstants.Title.PROJECT_INDEXER);
        Assertions.assertEquals("Vulnerability Indexing Service", NotificationConstants.Title.VULNERABILITY_INDEXER);
        Assertions.assertEquals("Core Indexing Services", NotificationConstants.Title.CORE_INDEXING_SERVICES);
        Assertions.assertEquals("File System Error", NotificationConstants.Title.FILE_SYSTEM_ERROR);
        Assertions.assertEquals("Repository Error", NotificationConstants.Title.REPO_ERROR);
        Assertions.assertEquals("Integration Error", NotificationConstants.Title.INTEGRATION_ERROR);
        Assertions.assertEquals("New Vulnerability Identified", NotificationConstants.Title.NEW_VULNERABILITY);
        Assertions.assertEquals("Vulnerable Dependency Introduced", NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY);
        Assertions.assertEquals("Analysis Decision: Exploitable", NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE);
        Assertions.assertEquals("Analysis Decision: In Triage", NotificationConstants.Title.ANALYSIS_DECISION_IN_TRIAGE);
        Assertions.assertEquals("Analysis Decision: False Positive", NotificationConstants.Title.ANALYSIS_DECISION_FALSE_POSITIVE);
        Assertions.assertEquals("Analysis Decision: Not Affected", NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED);
        Assertions.assertEquals("Analysis Decision: Marking Finding as NOT SET", NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET);
        Assertions.assertEquals("Analysis Decision: Finding Suppressed", NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED);
        Assertions.assertEquals("Analysis Decision: Finding UnSuppressed", NotificationConstants.Title.ANALYSIS_DECISION_UNSUPPRESSED);
        Assertions.assertEquals("Analysis Decision: Finding Resolved", NotificationConstants.Title.ANALYSIS_DECISION_RESOLVED);
    }
}
