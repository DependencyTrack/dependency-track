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

public class NotificationConstants {

    public static class Title {
        public static final String NOTIFICATION_TEST = "Notification Test";
        public static final String NVD_MIRROR = "NVD Mirroring";
        public static final String NPM_ADVISORY_MIRROR = "NPM Advisory Mirroring";
        public static final String VULNDB_MIRROR = "VulnDB Mirroring";
        public static final String COMPONENT_INDEXER = "Component Indexing Service";
        public static final String SERVICECOMPONENT_INDEXER = "ServiceComponent Indexing Service";
        public static final String LICENSE_INDEXER = "License Indexing Service";
        public static final String CPE_INDEXER = "CPE Indexing Service";
        public static final String VULNERABLESOFTWARE_INDEXER = "Vulnerable Software Indexer";
        public static final String PROJECT_INDEXER = "Project Indexing Service";
        public static final String VULNERABILITY_INDEXER = "Vulnerability Indexing Service";
        public static final String CORE_INDEXING_SERVICES = "Core Indexing Services";
        public static final String FILE_SYSTEM_ERROR = "File System Error";
        public static final String REPO_ERROR = "Repository Error";
        public static final String ANALYZER_ERROR = "Analyzer Error";
        public static final String INTEGRATION_ERROR = "Integration Error";
        public static final String NEW_VULNERABILITY = "New Vulnerability Identified";
        public static final String NEW_VULNERABLE_DEPENDENCY = "Vulnerable Dependency Introduced";
        public static final String ANALYSIS_DECISION_EXPLOITABLE = "Analysis Decision: Exploitable";
        public static final String ANALYSIS_DECISION_IN_TRIAGE = "Analysis Decision: In Triage";
        public static final String ANALYSIS_DECISION_FALSE_POSITIVE = "Analysis Decision: False Positive";
        public static final String ANALYSIS_DECISION_NOT_AFFECTED = "Analysis Decision: Not Affected";
        public static final String ANALYSIS_DECISION_NOT_SET = "Analysis Decision: Marking Finding as NOT SET";
        public static final String ANALYSIS_DECISION_SUPPRESSED = "Analysis Decision: Finding Suppressed";
        public static final String ANALYSIS_DECISION_UNSUPPRESSED = "Analysis Decision: Finding UnSuppressed";
        public static final String VIOLATIONANALYSIS_DECISION_APPROVED = "Violation Analysis Decision: Approved";
        public static final String VIOLATIONANALYSIS_DECISION_REJECTED = "Violation Analysis Decision: Rejected";
        public static final String VIOLATIONANALYSIS_DECISION_NOT_SET = "Violation Analysis Decision: Marking Finding as NOT SET";
        public static final String VIOLATIONANALYSIS_DECISION_SUPPRESSED = "Violation Analysis Decision: Violation Suppressed";
        public static final String VIOLATIONANALYSIS_DECISION_UNSUPPRESSED = "Violation Analysis Decision: Violation UnSuppressed";
        public static final String BOM_CONSUMED = "Bill of Materials Consumed";
        public static final String BOM_PROCESSED = "Bill of Materials Processed";
    }

}
