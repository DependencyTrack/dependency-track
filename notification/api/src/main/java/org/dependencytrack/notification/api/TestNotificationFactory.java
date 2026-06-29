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
package org.dependencytrack.notification.api;

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.notification.proto.v1.Bom;
import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Level;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitiesSummarySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Policy;
import org.dependencytrack.notification.proto.v1.PolicyCondition;
import org.dependencytrack.notification.proto.v1.PolicyViolation;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.Scope;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysis;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.NotificationFactory.createAnalyzerErrorNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createBomConsumedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createBomProcessedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createBomProcessingFailedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createBomValidationFailedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createIntegrationErrorNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerabilityNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createNewVulnerableDependencyNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createPolicyViolationNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createProjectCreatedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createUserCreatedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createUserDeletedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVexConsumedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVexProcessedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityRetractedNotification;
import static org.dependencytrack.notification.proto.v1.AnalysisTrigger.ANALYSIS_TRIGGER_BOM_UPLOAD;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_ANALYZER;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_INTEGRATION;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_POLICY_VIOLATIONS_SUMMARY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITIES_SUMMARY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_POLICY_VIOLATION;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_USER_CREATED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_USER_DELETED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VEX_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VULNERABILITY_RETRACTED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_SYSTEM;

/**
 * Factory for test notifications.
 *
 * @since 5.0.0
 */
public final class TestNotificationFactory {

    private record SupplierMatrixKey(
            Scope scope,
            Group group,
            Level level) {

        private SupplierMatrixKey {
            requireNonNull(level, "level must not be null");
            requireNonNull(scope, "scope must not be null");
            requireNonNull(group, "group must not be null");
        }

    }

    private static final Map<SupplierMatrixKey, Supplier<Notification>> SUPPLIER_MATRIX =
            Map.ofEntries(
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_VULNERABILITY_RETRACTED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createVulnerabilityRetractedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createBomConsumedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createBomProcessedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSING_FAILED, LEVEL_ERROR),
                            TestNotificationFactory::createBomProcessingFailedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_BOM_VALIDATION_FAILED, LEVEL_ERROR),
                            TestNotificationFactory::createBomValidationFailedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABILITY, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createNewVulnerabilityTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABLE_DEPENDENCY, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createNewVulnerableDependencyTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_POLICY_VIOLATION, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createPolicyViolationTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_PROJECT_AUDIT_CHANGE, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createProjectAuditChangeTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_PROJECT_CREATED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createProjectCreatedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_VEX_CONSUMED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createVexConsumedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_VEX_PROCESSED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createVexProcessedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_SYSTEM, GROUP_ANALYZER, LEVEL_ERROR),
                            TestNotificationFactory::createAnalyzerErrorTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_SYSTEM, GROUP_INTEGRATION, LEVEL_ERROR),
                            TestNotificationFactory::createIntegrationErrorTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_SYSTEM, GROUP_USER_CREATED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createUserCreatedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_SYSTEM, GROUP_USER_DELETED, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createUserDeletedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABILITIES_SUMMARY, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createNewVulnerabilitiesSummaryTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SCOPE_PORTFOLIO, GROUP_NEW_POLICY_VIOLATIONS_SUMMARY, LEVEL_INFORMATIONAL),
                            TestNotificationFactory::createNewPolicyViolationsSummaryTestNotification));

    private TestNotificationFactory() {
    }

    public static @Nullable Notification createTestNotification(
            Scope scope,
            Group group,
            Level level) {
        final Supplier<Notification> supplier =
                SUPPLIER_MATRIX.get(new SupplierMatrixKey(scope, group, level));
        if (supplier != null) {
            return supplier.get();
        }

        return null;
    }

    public static Notification createAnalyzerErrorTestNotification() {
        return createAnalyzerErrorNotification("failure");
    }

    public static Notification createVulnerabilityRetractedTestNotification() {
        return createVulnerabilityRetractedNotification(
                createProject(),
                createComponent(),
                createVulnerability());
    }

    public static Notification createBomConsumedTestNotification() {
        return createBomConsumedNotification(
                createProject(),
                createBom(),
                "eef2f6df-f03d-4cd4-954b-6ca1d73538e2");
    }

    public static Notification createBomProcessedTestNotification() {
        return createBomProcessedNotification(
                createProject(),
                createBom(),
                "eef2f6df-f03d-4cd4-954b-6ca1d73538e2");
    }

    public static Notification createBomProcessingFailedTestNotification() {
        return createBomProcessingFailedNotification(
                createProject(),
                createBom(),
                "eef2f6df-f03d-4cd4-954b-6ca1d73538e2",
                "cause");
    }

    public static Notification createBomValidationFailedTestNotification() {
        return createBomValidationFailedNotification(
                createProject(),
                List.of("cause 1", "cause 2"));
    }

    public static Notification createIntegrationErrorTestNotification() {
        return createIntegrationErrorNotification("failure");
    }

    public static Notification createNewVulnerabilityTestNotification() {
        return createNewVulnerabilityNotification(
                createProject(),
                createComponent(),
                createVulnerability(),
                ANALYSIS_TRIGGER_BOM_UPLOAD);
    }

    public static Notification createNewVulnerableDependencyTestNotification() {
        return createNewVulnerableDependencyNotification(
                createProject(),
                createComponent(),
                List.of(createVulnerability()));
    }

    public static Notification createPolicyViolationTestNotification() {
        return createPolicyViolationNotification(
                createProject(),
                createComponent(),
                createPolicyViolation(
                        createPolicyCondition(
                                createPolicy())));
    }

    public static Notification createProjectAuditChangeTestNotification() {
        return createVulnerabilityAnalysisDecisionChangeNotification(
                createProject(),
                createComponent(),
                createVulnerability(),
                createVulnerabilityAnalysis(
                        createProject(),
                        createComponent(),
                        createVulnerability()),
                true,
                false);
    }

    public static Notification createProjectCreatedTestNotification() {
        return createProjectCreatedNotification(createProject());
    }

    public static Notification createUserCreatedTestNotification() {
        return createUserCreatedNotification(createUser());
    }

    public static Notification createUserDeletedTestNotification() {
        return createUserDeletedNotification(createUser());
    }

    public static Notification createVexConsumedTestNotification() {
        return createVexConsumedNotification(createProject(), createBom());
    }

    public static Notification createVexProcessedTestNotification() {
        return createVexProcessedNotification(createProject(), createBom());
    }

    public static Notification createNewVulnerabilitiesSummaryTestNotification() {
        final Project project = createProject();
        final Component component = createComponent();
        final Vulnerability vulnerability = createVulnerability();

        final var finding = NewVulnerabilitiesSummarySubject.Finding.newBuilder()
                .setComponent(component)
                .setVulnerability(vulnerability)
                .setAnalyzerIdentity("internal")
                .setAttributedOn(Timestamps.fromSeconds(66666))
                .setAnalysisState("FALSE_POSITIVE")
                .setSuppressed(true)
                .build();

        final var sinceTimestamp = Timestamps.fromMillis(66666);

        final var subject = NewVulnerabilitiesSummarySubject.newBuilder()
                .setOverview(NewVulnerabilitiesSummarySubject.Overview.newBuilder()
                        .setAffectedProjectsCount(1)
                        .setAffectedComponentsCount(1)
                        .setNewVulnerabilitiesCount(0)
                        .setSuppressedNewVulnerabilitiesCount(1)
                        .setTotalNewVulnerabilitiesCount(1))
                .addProjectSummaries(NewVulnerabilitiesSummarySubject.ProjectSummaryEntry.newBuilder()
                        .setProject(project)
                        .putSuppressedNewVulnerabilitiesCountBySeverity("MEDIUM", 1)
                        .putTotalNewVulnerabilitiesCountBySeverity("MEDIUM", 1))
                .addFindingsByProject(NewVulnerabilitiesSummarySubject.ProjectFindingsEntry.newBuilder()
                        .setProject(project)
                        .addFindings(finding))
                .setSince(sinceTimestamp)
                .build();

        return NotificationFactory.createNewVulnerabilitiesSummaryNotification(subject);
    }

    public static Notification createNewPolicyViolationsSummaryTestNotification() {
        final Project project = createProject();
        final Component component = createComponent();
        final PolicyCondition condition = createScheduledPolicyCondition();

        final var violation = NewPolicyViolationsSummarySubject.Violation.newBuilder()
                .setUuid("924eaf86-454d-49f5-96c0-71d9008ac614")
                .setComponent(component)
                .setPolicyCondition(condition)
                .setType("LICENSE")
                .setTimestamp(Timestamps.fromSeconds(66666))
                .setAnalysisState("APPROVED")
                .setSuppressed(false)
                .build();

        final var sinceTimestamp = Timestamps.fromMillis(66666);

        final var subject = NewPolicyViolationsSummarySubject.newBuilder()
                .setOverview(NewPolicyViolationsSummarySubject.Overview.newBuilder()
                        .setAffectedProjectsCount(1)
                        .setAffectedComponentsCount(1)
                        .setNewViolationsCount(1)
                        .putNewViolationsCountByType("LICENSE", 1)
                        .setSuppressedNewViolationsCount(0)
                        .setTotalNewViolationsCount(1))
                .addProjectSummaries(NewPolicyViolationsSummarySubject.ProjectSummaryEntry.newBuilder()
                        .setProject(project)
                        .putNewViolationsCountByType("LICENSE", 1)
                        .putTotalNewViolationsCountByType("LICENSE", 1))
                .addViolationsByProject(NewPolicyViolationsSummarySubject.ProjectViolationsEntry.newBuilder()
                        .setProject(project)
                        .addViolations(violation))
                .setSince(sinceTimestamp)
                .build();

        return NotificationFactory.createNewPolicyViolationsSummaryNotification(subject);
    }

    private static Bom createBom() {
        return Bom.newBuilder()
                .setContent("bomContent")
                .setFormat("CycloneDX")
                .setSpecVersion("1.5")
                .build();
    }

    private static Component createComponent() {
        return Component.newBuilder()
                .setUuid("94f87321-a5d1-4c2f-b2fe-95165debebc6")
                .setName("componentName")
                .setVersion("componentVersion")
                .build();
    }

    private static Policy createPolicy() {
        return Policy.newBuilder()
                .setUuid("508cf29c-0216-479d-8975-35c9c6496932")
                .setName("policyName")
                .setViolationState("FAIL")
                .build();
    }

    private static PolicyCondition createPolicyCondition(Policy policy) {
        return PolicyCondition.newBuilder()
                .setUuid("61545b13-833e-44ed-aed1-717d7e15d530")
                .setPolicy(policy)
                .setSubject("PACKAGE_URL")
                .setOperator("IS")
                .setValue("pkg:maven/foo/bar@1.2.3")
                .build();
    }

    private static PolicyCondition createScheduledPolicyCondition() {
        return PolicyCondition.newBuilder()
                .setUuid("b029fce3-96f2-4c4a-9049-61070e9b6ea6")
                .setPolicy(createPolicy())
                .setSubject("AGE")
                .setOperator("NUMERIC_EQUAL")
                .setValue("P666D")
                .build();
    }

    private static PolicyViolation createPolicyViolation(PolicyCondition condition) {
        return PolicyViolation.newBuilder()
                .setUuid("26ca4bdc-ca15-4aee-a4be-75d5524c3572")
                .setCondition(condition)
                .setType("OPERATIONAL")
                .setTimestamp(Timestamps.now())
                .build();
    }

    private static Project createProject() {
        return Project.newBuilder()
                .setUuid("c9c9539a-e381-4b36-ac52-6a7ab83b2c95")
                .setName("projectName")
                .setVersion("projectVersion")
                .setDescription("projectDescription")
                .setPurl("pkg:maven/org.acme/projectName@projectVersion")
                .addAllTags(List.of("tag1", "tag2"))
                .setIsActive(true)
                .build();
    }

    private static UserSubject createUser() {
        return UserSubject.newBuilder()
                .setUsername("username")
                .setEmail("username@example.com")
                .build();
    }

    private static Vulnerability createVulnerability() {
        return Vulnerability.newBuilder()
                .setUuid("bccec5d5-ec21-4958-b3e8-22a7a866a05a")
                .setVulnId("INT-001")
                .setSource("INTERNAL")
                .addAliases(Vulnerability.Alias.newBuilder()
                        .setId("OSV-001")
                        .setSource("OSV")
                        .build())
                .setTitle("vulnerabilityTitle")
                .setSubTitle("vulnerabilitySubTitle")
                .setDescription("vulnerabilityDescription")
                .setRecommendation("vulnerabilityRecommendation")
                .setCvssV2(5.5)
                .setCvssV3(6.6)
                .setCvssV4(7.7)
                .setOwaspRrLikelihood(1.1)
                .setOwaspRrTechnicalImpact(2.2)
                .setOwaspRrBusinessImpact(3.3)
                .setSeverity("MEDIUM")
                .addCwes(Vulnerability.Cwe.newBuilder()
                        .setCweId(666)
                        .setName("Operation on Resource in Wrong Phase of Lifetime"))
                .addCwes(Vulnerability.Cwe.newBuilder()
                        .setCweId(777)
                        .setName("Regular Expression without Anchors"))
                .setIsKev(false)
                .build();
    }

    private static VulnerabilityAnalysis createVulnerabilityAnalysis(
            Project project,
            Component component,
            Vulnerability vulnerability) {
        return VulnerabilityAnalysis.newBuilder()
                .setProject(project)
                .setComponent(component)
                .setVulnerability(vulnerability)
                .setState("FALSE_POSITIVE")
                .setSuppressed(true)
                .build();
    }

}
