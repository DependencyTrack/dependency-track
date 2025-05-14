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
package org.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.pebbletemplates.pebble.error.ParserException;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.apache.commons.io.IOUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PolicyViolation.Type;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.BomValidationFailed;
import org.dependencytrack.notification.vo.NewPolicyViolationsSummary;
import org.dependencytrack.notification.vo.NewVulnerabilitiesSummary;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.ProjectFinding;
import org.dependencytrack.notification.vo.ProjectPolicyViolation;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.dependencytrack.util.NotificationUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

@WireMockTest
abstract class AbstractPublisherTest<T extends Publisher> extends PersistenceCapableTest {

    final DefaultNotificationPublishers publisher;
    final T publisherInstance;
    WireMockRuntimeInfo wmRuntimeInfo;

    AbstractPublisherTest(final DefaultNotificationPublishers publisher, final T publisherInstance) {
        this.publisher = publisher;
        this.publisherInstance = publisherInstance;
    }

    @BeforeEach
    final void initWmRuntimeInfo(WireMockRuntimeInfo wmRuntimeInfo) {
        this.wmRuntimeInfo = wmRuntimeInfo;
    }

    public final void baseTestInformWithBomConsumedNotification() {
        final var subject = new BomConsumedOrProcessed(createProject(), "bomContent", Bom.Format.CYCLONEDX, "1.5");

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_CONSUMED)
                .title(NotificationConstants.Title.BOM_CONSUMED)
                .content("A CycloneDX BOM was consumed and will be processed")
                .level(NotificationLevel.INFORMATIONAL)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithBomProcessingFailedNotification() {
        final var subject = new BomProcessingFailed(createProject(), "bomContent", "cause", Bom.Format.CYCLONEDX, "1.5");

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSING_FAILED)
                .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                .content("An error occurred while processing a BOM")
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithBomValidationFailedNotification() {
        final var errorsSample = List.of(
            "$.components[928].externalReferences[1].url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference");
        final var subject = new BomValidationFailed(createProject(), "bomContent", errorsSample, Bom.Format.CYCLONEDX);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_VALIDATION_FAILED)
                .title(NotificationConstants.Title.BOM_VALIDATION_FAILED)
                .content("An error occurred during BOM Validation")
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(1234, 888, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    // https://github.com/DependencyTrack/dependency-track/issues/3197
    public final void baseTestInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject() {
        final var subject = new BomProcessingFailed(createProject(), "bomContent", "cause", Bom.Format.CYCLONEDX, null);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSING_FAILED)
                .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                .content("An error occurred while processing a BOM")
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithDataSourceMirroringNotification() {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.DATASOURCE_MIRRORING)
                .title(NotificationConstants.Title.GITHUB_ADVISORY_MIRROR)
                .content("An error occurred mirroring the contents of GitHub Advisories. Check log for details.")
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC));

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithNewVulnerabilityNotification() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();

        final var subject = new NewVulnerabilityIdentified(vuln, component, Set.of(project),
                VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABILITY)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.NEW_VULNERABILITY)
                .content("")
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithNewVulnerableDependencyNotification() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();

        final var subject = new NewVulnerableDependency(component, List.of(vuln));

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABLE_DEPENDENCY)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY)
                .content("")
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithProjectAuditChangeNotification() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();
        final var analysis = createAnalysis(component, vuln);

        final var subject = new AnalysisDecisionChange(vuln, component, project, analysis);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.PROJECT_AUDIT_CHANGE)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED)
                .content("")
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestInformWithEscapedData() {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.NOTIFICATION_TEST)
                .content("! \" § $ % & / ( ) = ? \\ ' * Ö Ü Ä ®️")
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC));

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    @Test
    public void testInformWithTemplateInclude() throws Exception {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.NOTIFICATION_TEST)
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC));

        final JsonObject config = Json.createObjectBuilder(createConfig())
                .add(Publisher.CONFIG_TEMPLATE_KEY, "{% include '/some/path' %}")
                .build();

        assertThatExceptionOfType(ParserException.class)
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, config))
                .withMessage("Unexpected tag name \"include\" ({% include '/some/path' %}:1)");
    }

    public final void baseTestPublishWithScheduledNewVulnerabilitiesNotification() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();

        final var findingsByProject = Map.of(project, List.of(new ProjectFinding(
                component, vuln, AnalyzerIdentity.INTERNAL_ANALYZER, Date.from(Instant.ofEpochSecond(66666, 666)),
                "", AnalysisState.FALSE_POSITIVE, true)));

        final var subject = NewVulnerabilitiesSummary.of(findingsByProject, new Date(66666), 666);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABILITIES_SUMMARY)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.NEW_VULNERABILITIES_SUMMARY)
                .content(NotificationUtil.generateNotificationContent(subject))
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    public final void baseTestPublishWithScheduledNewPolicyViolationsNotification() {
        final var violation = createPolicyViolation();

        final var violationsByProject = Map.of(violation.getProject(), List.of(new ProjectPolicyViolation(
                UUID.fromString("924eaf86-454d-49f5-96c0-71d9008ac614"),
                violation.getComponent(),
                violation.getPolicyCondition(),
                violation.getType(),
                violation.getTimestamp(),
                violation.getAnalysis().getAnalysisState(),
                violation.getAnalysis().isSuppressed())));

        final var subject = NewPolicyViolationsSummary.of(violationsByProject, new Date(66666), 666);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.NEW_POLICY_VIOLATIONS_SUMMARY)
                .content(NotificationUtil.generateNotificationContent(subject))
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC))
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, createConfig()));
    }

    protected Notification createNotificationWithNotifySeverities(List<Severity> notifySeverities) {
        // build the Notification itself
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        notification.setTitle(NotificationConstants.Title.NEW_VULNERABILITY);
        notification.setContent("");
        notification.setTimestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC));
        var project   = createProject();
        var component = createComponent(project);
        var vuln      = createVulnerability(); // sets severity = MEDIUM
        notification.setSubject(new NewVulnerabilityIdentified(vuln, component, Set.of(project), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        // create + persist the NotificationPublisher
        String template;
        try {
            template = IOUtils.resourceToString(publisher.getPublisherTemplateFile(), UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        NotificationPublisher np = qm.createNotificationPublisher(
                publisher.getPublisherName(),
                publisher.getPublisherDescription(),
                publisher.getPublisherClass(),
                template,
                publisher.getTemplateMimeType(),
                publisher.isDefaultPublisher()
        );

        // create + persist the NotificationRule that the router will query
        NotificationRule rule = qm.createNotificationRule(
                "Test Rule",
                NotificationScope.PORTFOLIO,
                NotificationLevel.INFORMATIONAL,
                np
        );
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
        rule.setNotifySeverities(notifySeverities);
        try {
            rule.setPublisherConfig(String.valueOf(createConfig()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return notification;
    }

    private static Component createComponent(final Project project) {
        final var component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("94f87321-a5d1-4c2f-b2fe-95165debebc6"));
        component.setName("componentName");
        component.setVersion("componentVersion");
        return component;
    }

    private static Project createProject() {
        final var projectTag1 = new Tag();
        projectTag1.setName("tag1");
        final var projectTag2 = new Tag();
        projectTag2.setName("tag2");

        final var project = new Project();
        project.setUuid(UUID.fromString("c9c9539a-e381-4b36-ac52-6a7ab83b2c95"));
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("pkg:maven/org.acme/projectName@projectVersion");
        project.setTags(Set.of(projectTag1, projectTag2));
        return project;
    }

    private static Vulnerability createVulnerability() {
        final var alias = new org.dependencytrack.model.VulnerabilityAlias();
        alias.setInternalId("INT-001");
        alias.setOsvId("OSV-001");

        final var vuln = new org.dependencytrack.model.Vulnerability();
        vuln.setUuid(UUID.fromString("bccec5d5-ec21-4958-b3e8-22a7a866a05a"));
        vuln.setVulnId("INT-001");
        vuln.setSource(org.dependencytrack.model.Vulnerability.Source.INTERNAL);
        vuln.setAliases(List.of(alias));
        vuln.setTitle("vulnerabilityTitle");
        vuln.setSubTitle("vulnerabilitySubTitle");
        vuln.setDescription("vulnerabilityDescription");
        vuln.setRecommendation("vulnerabilityRecommendation");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(5.5));
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(6.6));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(1.1));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(2.2));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCwes(List.of(666, 777));
        return vuln;
    }

    private static Analysis createAnalysis(final Component component, final Vulnerability vuln) {
        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.FALSE_POSITIVE);
        analysis.setSuppressed(true);
        return analysis;
    }

    private static Policy createPolicy() {
        final var policy = new Policy();
        policy.setUuid(UUID.fromString("8d2f1ec1-3625-48c6-97c4-2a7553c7a376"));
        policy.setViolationState(ViolationState.INFO);
        policy.setName("policyName");
        return policy;
    }

    private static ViolationAnalysis createViolationAnalysis() {
        final var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        violationAnalysis.setSuppressed(false);
        return violationAnalysis;
    }

    private static PolicyCondition createPolicyCondition() {
        final var policy = createPolicy();
        final var policyCondition = new PolicyCondition();
        policyCondition.setUuid(UUID.fromString("b029fce3-96f2-4c4a-9049-61070e9b6ea6"));
        policyCondition.setPolicy(policy);
        policyCondition.setSubject(PolicyCondition.Subject.AGE);
        policyCondition.setOperator(Operator.NUMERIC_EQUAL);
        policyCondition.setValue("P666D");
        return policyCondition;
    }

    private static PolicyViolation createPolicyViolation() {
        final var project = createProject();
        final var component = createComponent(project);
        final var violation = new PolicyViolation();
        final var violationAnalysis = createViolationAnalysis();
        final var policyCondition = createPolicyCondition();

        violation.setUuid(UUID.fromString("bf956a83-6013-4a69-9c76-857e2a8c8e45"));
        violation.setPolicyCondition(policyCondition);
        violation.setType(Type.LICENSE);
        violation.setComponent(component);
        violation.setTimestamp(Date.from(Instant.ofEpochSecond(66666, 666))); // Thu Jan 01 18:31:06 GMT 1970
        violation.setAnalysis(violationAnalysis);
        return violation;
    }

    JsonObject createConfig() throws IOException {
        return Json.createObjectBuilder()
                .add(Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY, publisher.getTemplateMimeType())
                .add(Publisher.CONFIG_TEMPLATE_KEY, IOUtils.resourceToString(publisher.getPublisherTemplateFile(), UTF_8))
                .addAll(extraConfig())
                .build();
    }

    JsonObjectBuilder extraConfig() {
        return Json.createObjectBuilder();
    }

}
