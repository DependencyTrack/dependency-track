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
package org.dependencytrack.util;

import alpine.model.ConfigProperty;
import alpine.model.UserPrincipal;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.FileUtils;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.BomValidationFailed;
import org.dependencytrack.notification.vo.NewPolicyViolationsSummary;
import org.dependencytrack.notification.vo.NewVulnerabilitiesSummary;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.ProjectFinding;
import org.dependencytrack.notification.vo.ProjectPolicyViolation;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import javax.jdo.FetchPlan;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class NotificationUtil {

    /**
     * Private constructor.
     */
    private NotificationUtil() { }

    public static void analyzeNotificationCriteria(QueryManager qm, Vulnerability vulnerability, Component component, VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        if (!qm.contains(vulnerability, component)) {
            // Component did not previously contain this vulnerability. It could be a newly discovered vulnerability
            // against an existing component, or it could be a newly added (and vulnerable) component. Either way,
            // it warrants a Notification be dispatched.
            final Map<Long,Project> affectedProjects = new HashMap<>();
            final List<Component> components = qm.matchIdentity(new ComponentIdentity(component));
            for (final Component c : components) {
                if(!affectedProjects.containsKey(c.getProject().getId())) {
                    affectedProjects.put(c.getProject().getId(), qm.detach(Project.class, c.getProject().getId()));
                }
            }

            final Vulnerability detachedVuln =  qm.detach(Vulnerability.class, vulnerability.getId());
            detachedVuln.setAliases(qm.detach(qm.getVulnerabilityAliases(vulnerability))); // Aliases are lost during detach above
            final Component detachedComponent = qm.detach(Component.class, component.getId());

            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.NEW_VULNERABILITY)
                    .title(generateNotificationTitle(NotificationConstants.Title.NEW_VULNERABILITY, component.getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(detachedVuln))
                    .subject(new NewVulnerabilityIdentified(detachedVuln, detachedComponent, new HashSet<>(affectedProjects.values()), vulnerabilityAnalysisLevel))
            );
        }
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, Component component) {
        List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component, false);
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            component = qm.detach(Component.class, component.getId());
            vulnerabilities = qm.detach(vulnerabilities);
            for (final Vulnerability vulnerability : vulnerabilities) {
                // Because aliases is a transient field, it's lost when detaching the vulnerability.
                // Repopulating here as a workaround, ultimately we need a better way to handle them.
                vulnerability.setAliases(qm.detach(qm.getVulnerabilityAliases(vulnerability)));
            }

            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.NEW_VULNERABLE_DEPENDENCY)
                    .title(generateNotificationTitle(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY, component.getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(component, vulnerabilities))
                    .subject(new NewVulnerableDependency(component, vulnerabilities))
            );
        }
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, Analysis analysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;

            String title = null;
            if (analysisStateChange) {
                switch (analysis.getAnalysisState()) {
                    case EXPLOITABLE:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE;
                        break;
                    case IN_TRIAGE:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_IN_TRIAGE;
                        break;
                    case NOT_AFFECTED:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED;
                        break;
                    case FALSE_POSITIVE:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_FALSE_POSITIVE;
                        break;
                    case NOT_SET:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET;
                        break;
                    case RESOLVED:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_RESOLVED;
                        break;
                }
            } else if (suppressionChange) {
                if (analysis.isSuppressed()) {
                    title = NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED;
                } else {
                    title = NotificationConstants.Title.ANALYSIS_DECISION_UNSUPPRESSED;
                }
            }

            Project project = analysis.getComponent().getProject();

            analysis = qm.detach(Analysis.class, analysis.getId());

            analysis.getComponent().setProject(project); // Project of component is lost after the detach above

            // Aliases are lost during the detach above
            analysis.getVulnerability().setAliases(qm.detach(qm.getVulnerabilityAliases(analysis.getVulnerability())));

            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(generateNotificationTitle(title, analysis.getComponent().getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(analysis))
                    .subject(new AnalysisDecisionChange(analysis.getVulnerability(),
                            analysis.getComponent(), analysis.getProject(), analysis))
            );
        }
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, ViolationAnalysis violationAnalysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;
            String title = null;
            if (analysisStateChange) {
                switch (violationAnalysis.getAnalysisState()) {
                    case APPROVED:
                        title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_APPROVED;
                        break;
                    case REJECTED:
                        title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_REJECTED;
                        break;
                    case NOT_SET:
                        title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_NOT_SET;
                        break;
                }
            } else if (suppressionChange) {
                if (violationAnalysis.isSuppressed()) {
                    title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_SUPPRESSED;
                } else {
                    title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_UNSUPPRESSED;
                }
            }

            Project project = violationAnalysis.getComponent().getProject();
            PolicyViolation policyViolation = violationAnalysis.getPolicyViolation();
            policyViolation.getPolicyCondition().getPolicy(); // Force loading of policy

            violationAnalysis = qm.detach(ViolationAnalysis.class, violationAnalysis.getId());

            violationAnalysis.getComponent().setProject(project); // Project of component is lost after the detach above
            violationAnalysis.setPolicyViolation(policyViolation); // PolicyCondition and policy of policyViolation is lost after the detach above

            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(generateNotificationTitle(title, violationAnalysis.getComponent().getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(violationAnalysis))
                    .subject(new ViolationAnalysisDecisionChange(violationAnalysis.getPolicyViolation(),
                            violationAnalysis.getComponent(), violationAnalysis))
            );
        }
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, final PolicyViolation policyViolation) {
        final ViolationAnalysis violationAnalysis = qm.getViolationAnalysis(policyViolation.getComponent(), policyViolation);
        if (violationAnalysis != null && (violationAnalysis.isSuppressed() || ViolationAnalysisState.APPROVED == violationAnalysis.getAnalysisState())) return;
        policyViolation.getPolicyCondition().getPolicy(); // Force loading of policy
        qm.getPersistenceManager().getFetchPlan().setMaxFetchDepth(3); // Ensure policy is included
        qm.getPersistenceManager().getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final PolicyViolation pv = qm.getPersistenceManager().detachCopy(policyViolation);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.POLICY_VIOLATION)
                .title(generateNotificationTitle(NotificationConstants.Title.POLICY_VIOLATION,policyViolation.getComponent().getProject()))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(pv))
                .subject(new PolicyViolationIdentified(pv, pv.getComponent(), pv.getProject()))
        );
    }

    public static JsonObject toJson(final Project project) {
        final JsonObjectBuilder projectBuilder = Json.createObjectBuilder();
        projectBuilder.add("uuid", project.getUuid().toString());
        JsonUtil.add(projectBuilder, "name", project.getName());
        JsonUtil.add(projectBuilder, "version", project.getVersion());
        JsonUtil.add(projectBuilder, "description", project.getDescription());
        if (project.getPurl() != null) {
            projectBuilder.add("purl", project.getPurl().canonicalize());
        }
        if (project.getTags() != null && project.getTags().size() > 0) {
            final StringBuilder sb = new StringBuilder();
            for (final Tag tag: project.getTags()) {
                sb.append(tag.getName()).append(",");
            }
            String tags = sb.toString();
            if (tags.endsWith(",")) {
                tags = tags.substring(0, tags.length()-1);
            }
            JsonUtil.add(projectBuilder, "tags", tags);
        }
        return projectBuilder.build();
    }

    public static JsonObject toJson(final UserPrincipal user) {
        final JsonObjectBuilder userBuilder = Json.createObjectBuilder();

        userBuilder.add("username", user.getUsername());

        if (user.getName() != null) {
            userBuilder.add("name", user.getName());
        }

        if (user.getEmail() != null) {
            userBuilder.add("email", user.getEmail());
        }

        return userBuilder.build();
    }

    public static JsonObject toJson(final Component component) {
        final JsonObjectBuilder componentBuilder = Json.createObjectBuilder();
        componentBuilder.add("uuid", component.getUuid().toString());
        JsonUtil.add(componentBuilder, "group", component.getGroup());
        JsonUtil.add(componentBuilder, "name", component.getName());
        JsonUtil.add(componentBuilder, "version", component.getVersion());
        JsonUtil.add(componentBuilder, "md5", component.getMd5());
        JsonUtil.add(componentBuilder, "sha1", component.getSha1());
        JsonUtil.add(componentBuilder, "sha256", component.getSha256());
        JsonUtil.add(componentBuilder, "sha512", component.getSha512());
        if (component.getPurl() != null) {
            componentBuilder.add("purl", component.getPurl().canonicalize());
        }
        return componentBuilder.build();
    }

    public static JsonObject toJson(final Vulnerability vulnerability) {
        final JsonObjectBuilder vulnerabilityBuilder = Json.createObjectBuilder();
        vulnerabilityBuilder.add("uuid", vulnerability.getUuid().toString());
        JsonUtil.add(vulnerabilityBuilder, "vulnId", vulnerability.getVulnId());
        JsonUtil.add(vulnerabilityBuilder, "source", vulnerability.getSource());
        final JsonArrayBuilder aliasesBuilder = Json.createArrayBuilder();
        if (vulnerability.getAliases() != null) {
            for (final Map.Entry<Vulnerability.Source, String> vulnIdBySource : VulnerabilityUtil.getUniqueAliases(vulnerability)) {
                aliasesBuilder.add(Json.createObjectBuilder()
                        .add("source", vulnIdBySource.getKey().name())
                        .add("vulnId", vulnIdBySource.getValue())
                        .build());
            }
        }
        vulnerabilityBuilder.add("aliases", aliasesBuilder.build());
        JsonUtil.add(vulnerabilityBuilder, "title", vulnerability.getTitle());
        JsonUtil.add(vulnerabilityBuilder, "subtitle", vulnerability.getSubTitle());
        JsonUtil.add(vulnerabilityBuilder, "description", vulnerability.getDescription());
        JsonUtil.add(vulnerabilityBuilder, "recommendation", vulnerability.getRecommendation());
        JsonUtil.add(vulnerabilityBuilder, "cvssv2", vulnerability.getCvssV2BaseScore());
        JsonUtil.add(vulnerabilityBuilder, "cvssv3", vulnerability.getCvssV3BaseScore());
        JsonUtil.add(vulnerabilityBuilder, "owaspRRLikelihood", vulnerability.getOwaspRRLikelihoodScore());
        JsonUtil.add(vulnerabilityBuilder, "owaspRRTechnicalImpact", vulnerability.getOwaspRRTechnicalImpactScore());
        JsonUtil.add(vulnerabilityBuilder, "owaspRRBusinessImpact", vulnerability.getOwaspRRBusinessImpactScore());
        JsonUtil.add(vulnerabilityBuilder, "severity",  vulnerability.getSeverity());
        final JsonArrayBuilder cwesBuilder = Json.createArrayBuilder();
        if (vulnerability.getCwes() != null) {
            for (final Integer cweId: vulnerability.getCwes()) {
                final Cwe cwe = CweResolver.getInstance().lookup(cweId);
                if (cwe != null) {
                    final JsonObject cweNode = Json.createObjectBuilder()
                            .add("cweId", cwe.getCweId())
                            .add("name", cwe.getName())
                            .build();
                    cwesBuilder.add(cweNode);
                }
            }
        }
        final JsonArray cwes = cwesBuilder.build();
        if (cwes != null && !cwes.isEmpty()) {
            // Ensure backwards-compatibility with DT < 4.5.0. Remove this in v5!
            vulnerabilityBuilder.add("cwe", cwes.getJsonObject(0));
        }
        vulnerabilityBuilder.add("cwes", cwes);
        return vulnerabilityBuilder.build();
    }

    public static JsonObject toJson(final Analysis analysis) {
        final JsonObjectBuilder analysisBuilder = Json.createObjectBuilder();
        analysisBuilder.add("suppressed", analysis.isSuppressed());
        JsonUtil.add(analysisBuilder, "state", analysis.getAnalysisState());
        if (analysis.getProject() != null) {
            JsonUtil.add(analysisBuilder, "project", analysis.getProject().getUuid().toString());
        }
        JsonUtil.add(analysisBuilder, "component", analysis.getComponent().getUuid().toString());
        JsonUtil.add(analysisBuilder, "vulnerability", analysis.getVulnerability().getUuid().toString());
        return analysisBuilder.build();
    }

    public static JsonObject toJson(final ViolationAnalysis violationAnalysis) {
        final JsonObjectBuilder violationAnalysisBuilder = Json.createObjectBuilder();
        violationAnalysisBuilder.add("suppressed", violationAnalysis.isSuppressed());
        JsonUtil.add(violationAnalysisBuilder, "state", violationAnalysis.getAnalysisState());
        if (violationAnalysis.getProject() != null) {
            JsonUtil.add(violationAnalysisBuilder, "project", violationAnalysis.getProject().getUuid().toString());
        }
        JsonUtil.add(violationAnalysisBuilder, "component", violationAnalysis.getComponent().getUuid().toString());
        JsonUtil.add(violationAnalysisBuilder, "policyViolation", violationAnalysis.getPolicyViolation().getUuid().toString());
        return violationAnalysisBuilder.build();
    }

    public static JsonObject toJson(final NewVulnerabilityIdentified vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getComponent() != null) {
            builder.add("component", toJson(vo.getComponent()));
        }
        if (vo.getVulnerabilityAnalysisLevel() != null) {
            builder.add("vulnerabilityAnalysisLevel", vo.getVulnerabilityAnalysisLevel().toString());
        }
        if (vo.getVulnerability() != null) {
            builder.add("vulnerability", toJson(vo.getVulnerability()));
        }
        if (vo.getAffectedProjects() != null && vo.getAffectedProjects().size() > 0) {
            final JsonArrayBuilder projectsBuilder = Json.createArrayBuilder();
            for (final Project project: vo.getAffectedProjects()) {
                projectsBuilder.add(toJson(project));
            }
            builder.add("affectedProjects", projectsBuilder.build());
        }
        return builder.build();
    }

    public static JsonObject toJson(final NewVulnerableDependency vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getComponent().getProject() != null) {
            builder.add("project", toJson(vo.getComponent().getProject()));
        }
        if (vo.getComponent() != null) {
            builder.add("component", toJson(vo.getComponent()));
        }
        if (vo.getVulnerabilities() != null && vo.getVulnerabilities().size() > 0) {
            final JsonArrayBuilder vulnsBuilder = Json.createArrayBuilder();
            for (final Vulnerability vulnerability : vo.getVulnerabilities()) {
                vulnsBuilder.add(toJson(vulnerability));
            }
            builder.add("vulnerabilities", vulnsBuilder.build());
        }
        return builder.build();
    }

    public static JsonObject toJson(final AnalysisDecisionChange vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getComponent() != null) {
            builder.add("component", toJson(vo.getComponent()));
        }
        if (vo.getVulnerability() != null) {
            builder.add("vulnerability", toJson(vo.getVulnerability()));
        }
        if (vo.getAnalysis() != null) {
            builder.add("analysis", toJson(vo.getAnalysis()));
        }
        if (vo.getProject() != null) {
            // Provide the affected project in the form of an array for backwards-compatibility
            builder.add("affectedProjects", Json.createArrayBuilder().add(toJson(vo.getProject())));
        }
        return builder.build();
    }

    public static JsonObject toJson(final ViolationAnalysisDecisionChange vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getComponent() != null) {
            builder.add("component", toJson(vo.getComponent()));
        }
        if (vo.getPolicyViolation() != null) {
            builder.add("policyViolation", toJson(vo.getPolicyViolation()));
        }
        if (vo.getViolationAnalysis() != null) {
            builder.add("violationAnalysis", toJson(vo.getViolationAnalysis()));
        }
        return builder.build();
    }

    public static JsonObject toJson(final BomConsumedOrProcessed vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getProject() != null) {
            builder.add("project", toJson(vo.getProject()));
        }
        if (vo.getBom() != null) {
            builder.add("bom", Json.createObjectBuilder()
                    .add("content", vo.getBom())
                    .add("format", vo.getFormat().getFormatShortName())
                    .add("specVersion", vo.getSpecVersion()).build()
            );
        }
        return builder.build();
    }

    public static JsonObject toJson(final BomProcessingFailed vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getProject() != null) {
            builder.add("project", toJson(vo.getProject()));
        }
        if (vo.getBom() != null) {
            builder.add("bom", Json.createObjectBuilder()
                    .add("content", Optional.ofNullable(vo.getBom()).orElse("Unknown"))
                    .add("format", Optional.ofNullable(vo.getFormat()).map(Bom.Format::getFormatShortName).orElse("Unknown"))
                    .add("specVersion", Optional.ofNullable(vo.getSpecVersion()).orElse("Unknown")).build()
            );
        }
        if (vo.getCause() != null) {
            builder.add("cause", vo.getCause());
        }
        return builder.build();
    }

    public static JsonObject toJson(final BomValidationFailed vo) {
        final var builder = Json.createObjectBuilder();
        if (vo.getProject() != null) {
            builder.add("project", toJson(vo.getProject()));
        }
        if (vo.getBom() != null) {
            builder.add("bom", Json.createObjectBuilder()
                    .add("content", Optional.ofNullable(vo.getBom()).orElse("Unknown"))
                    .add("format", Optional.ofNullable(vo.getFormat()).map(Bom.Format::getFormatShortName).orElse("Unknown"))
                    .build()
            );
        }
        final var errors = vo.getErrors();
        if (errors != null && !errors.isEmpty()) {
            final var commaSeparatedErrors = String.join(",", errors);
            JsonUtil.add(builder, "errors", commaSeparatedErrors);
        }
        return builder.build();
    }

    public static JsonObject toJson(final VexConsumedOrProcessed vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getProject() != null) {
            builder.add("project", toJson(vo.getProject()));
        }
        if (vo.getVex() != null) {
            builder.add("vex", Json.createObjectBuilder()
                    .add("content", vo.getVex())
                    .add("format", vo.getFormat().getFormatShortName())
                    .add("specVersion", vo.getSpecVersion()).build()
            );
        }
        return builder.build();
    }

    public static JsonObject toJson(final PolicyViolationIdentified vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getComponent().getProject() != null) {
            builder.add("project", toJson(vo.getComponent().getProject()));
        }
        if (vo.getComponent() != null) {
            builder.add("component", toJson(vo.getComponent()));
        }
        if (vo.getPolicyViolation() != null) {
            builder.add("policyViolation", toJson(vo.getPolicyViolation()));
        }
        return builder.build();
    }

    public static JsonObject toJson(final NewPolicyViolationsSummary vo) {
        return Json.createObjectBuilder()
                .add("overview", toJson(vo.overview()))
                .add("summary", toJson(vo.summary()))
                .add("details", toJson(vo.details()))
                .add("since", DateUtil.toISO8601(vo.since()))
                .build();
    }

    private static JsonObject toJson(final NewPolicyViolationsSummary.Overview vo) {
        return Json.createObjectBuilder()
                .add("affectedProjectsCount", vo.affectedProjectsCount())
                .add("affectedComponentsCount", vo.affectedComponentsCount())
                .add("newViolationsCount", vo.newViolationsCount())
                .add("suppressedNewViolationsCount", vo.suppressedNewViolationsCount())
                .add("totalNewViolationsCount", vo.totalNewViolationsCount())
                .build();
    }

    private static JsonObject toJson(final NewPolicyViolationsSummary.Summary vo) {
        final var projectSummariesBuilder = Json.createArrayBuilder();
        for (final Map.Entry<Project, NewPolicyViolationsSummary.ProjectSummary> entry : vo.projectSummaries().entrySet()) {
            projectSummariesBuilder.add(
                    Json.createObjectBuilder()
                            .add("project", toJson(entry.getKey()))
                            .add("summary", toJson(entry.getValue())));
        }

        return Json.createObjectBuilder()
                .add("projectSummaries", projectSummariesBuilder)
                .build();
    }

    private static JsonObject toJson(final NewPolicyViolationsSummary.ProjectSummary vo) {
        return Json.createObjectBuilder()
                .add("newViolationsCountByType", violationTypeCountMapToJson(vo.newViolationsCountByType()))
                .add("suppressedNewViolationsCountByType", violationTypeCountMapToJson(vo.suppressedNewViolationsCountByType()))
                .add("totalNewViolationsCountByType", violationTypeCountMapToJson(vo.totalNewViolationsCountByType()))
                .build();
    }

    private static JsonObject toJson(final NewPolicyViolationsSummary.Details vo) {
        final JsonArrayBuilder violationsByProjectBuilder = Json.createArrayBuilder();
        for (final Map.Entry<Project, List<ProjectPolicyViolation>> entry : vo.violationsByProject().entrySet()) {
            final JsonArrayBuilder violationsBuilder = Json.createArrayBuilder();
            for (final ProjectPolicyViolation violation : entry.getValue()) {
                violationsBuilder.add(toJson(violation));
            }

            violationsByProjectBuilder.add(
                    Json.createObjectBuilder()
                            .add("project", toJson(entry.getKey()))
                            .add("violations", violationsBuilder));
        }

        return Json.createObjectBuilder()
                .add("violationsByProject", violationsByProjectBuilder)
                .build();
    }

    private static JsonObject toJson(final ProjectPolicyViolation vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("uuid", vo.uuid().toString())
                .add("component", toJson(vo.component()))
                .add("policyCondition", toJson(vo.policyCondition()))
                .add("type", vo.type().name())
                .add("timestamp", DateUtil.toISO8601(vo.timestamp()))
                .add("suppressed", vo.suppressed());
        if (vo.analysisState() != null) {
            builder.add("analysisState", vo.analysisState().name());
        }
        return builder.build();
    }

    private static JsonObject violationTypeCountMapToJson(final Map<PolicyViolation.Type, Integer> map) {
        final var builder = Json.createObjectBuilder();
        for (final Map.Entry<PolicyViolation.Type, Integer> entry : map.entrySet()) {
            builder.add(entry.getKey().name(), entry.getValue());
        }
        return builder.build();
    }

    public static JsonObject toJson(final NewVulnerabilitiesSummary vo) {
        return Json.createObjectBuilder()
                .add("overview", toJson(vo.overview()))
                .add("summary", toJson(vo.summary()))
                .add("details", toJson(vo.details()))
                .add("since", DateUtil.toISO8601(vo.since()))
                .build();
    }

    private static JsonObject toJson(final NewVulnerabilitiesSummary.Overview vo) {
        return Json.createObjectBuilder()
                .add("affectedProjectsCount", vo.affectedProjectsCount())
                .add("affectedComponentsCount", vo.affectedComponentsCount())
                .add("newVulnerabilitiesCount", vo.newVulnerabilitiesCount())
                .add("newVulnerabilitiesCountBySeverity", severityCountMapToJson(vo.newVulnerabilitiesCountBySeverity()))
                .add("suppressedNewVulnerabilitiesCount", vo.suppressedNewVulnerabilitiesCount())
                .add("totalNewVulnerabilitiesCount", vo.totalNewVulnerabilitiesCount())
                .build();
    }

    private static JsonObject toJson(final NewVulnerabilitiesSummary.Summary vo) {
        final var projectSummariesBuilder = Json.createArrayBuilder();
        for (final Map.Entry<Project, NewVulnerabilitiesSummary.ProjectSummary> entry : vo.projectSummaries().entrySet()) {
            projectSummariesBuilder.add(Json.createObjectBuilder()
                    .add("project", toJson(entry.getKey()))
                    .add("summary", toJson(entry.getValue())));
        }

        return Json.createObjectBuilder()
                .add("projectSummaries", projectSummariesBuilder)
                .build();
    }

    private static JsonObject toJson(final NewVulnerabilitiesSummary.ProjectSummary vo) {
        return Json.createObjectBuilder()
                .add("newVulnerabilitiesCountBySeverity", severityCountMapToJson(vo.newVulnerabilitiesCountBySeverity()))
                .add("suppressedNewVulnerabilitiesCountBySeverity", severityCountMapToJson(vo.suppressedNewVulnerabilitiesCountBySeverity()))
                .add("totalNewVulnerabilitiesCountBySeverity", severityCountMapToJson(vo.totalNewVulnerabilitiesCountBySeverity()))
                .build();
    }

    private static JsonObject toJson(final NewVulnerabilitiesSummary.Details vo) {
        final JsonArrayBuilder findingsByProjectBuilder = Json.createArrayBuilder();
        for (final Map.Entry<Project, List<ProjectFinding>> entry : vo.findingsByProject().entrySet()) {
            final JsonArrayBuilder findingsBuilder = Json.createArrayBuilder();
            for (final ProjectFinding finding : entry.getValue()) {
                findingsBuilder.add(toJson(finding));
            }

            findingsByProjectBuilder.add(
                    Json.createObjectBuilder()
                            .add("project", toJson(entry.getKey()))
                            .add("findings", findingsBuilder));
        }

        return Json.createObjectBuilder()
                .add("findingsByProject", findingsByProjectBuilder)
                .build();
    }

    private static JsonObject toJson(final ProjectFinding vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("component", toJson(vo.component()))
                .add("vulnerability", toJson(vo.vulnerability()))
                .add("analyzer", vo.analyzerIdentity().name())
                .add("attributedOn", DateUtil.toISO8601(vo.attributedOn()))
                .add("suppressed", vo.suppressed());
        if (vo.analysisState() != null) {
            builder.add("analysisState", vo.analysisState().name());
        }
        return builder.build();
    }

    private static JsonObject severityCountMapToJson(final Map<Severity, Integer> map) {
        final var builder = Json.createObjectBuilder();
        for (final Map.Entry<Severity, Integer> entry : map.entrySet()) {
            builder.add(entry.getKey().name(), entry.getValue());
        }
        return builder.build();
    }

    public static JsonObject toJson(final PolicyViolation pv) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("uuid", pv.getUuid().toString());
        builder.add("type", pv.getType().name());
        builder.add("timestamp", DateUtil.toISO8601(pv.getTimestamp()));
        builder.add("policyCondition", toJson(pv.getPolicyCondition()));
        return builder.build();
    }

    public static JsonObject toJson(final PolicyCondition pc) {
        final JsonObjectBuilder componentBuilder = Json.createObjectBuilder();
        componentBuilder.add("uuid", pc.getUuid().toString());
        JsonUtil.add(componentBuilder, "subject", pc.getSubject().name());
        JsonUtil.add(componentBuilder, "operator", pc.getOperator().name());
        JsonUtil.add(componentBuilder, "value", pc.getValue());
        componentBuilder.add("policy", toJson(pc.getPolicy()));
        return componentBuilder.build();
    }

    public static JsonObject toJson(final Policy policy) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("uuid", policy.getUuid().toString());
        builder.add("name", policy.getName());
        builder.add("violationState", policy.getViolationState().name());
        return builder.build();
    }

    public static void loadDefaultNotificationPublishers(QueryManager qm) throws IOException {
        for (final DefaultNotificationPublishers publisher : DefaultNotificationPublishers.values()) {
            File templateFile = new File(URLDecoder.decode(NotificationUtil.class.getResource(publisher.getPublisherTemplateFile()).getFile(), UTF_8.name()));
            if (qm.isEnabled(ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED)) {
                ConfigProperty templateBaseDir = qm.getConfigProperty(
                        ConfigPropertyConstants.NOTIFICATION_TEMPLATE_BASE_DIR.getGroupName(),
                        ConfigPropertyConstants.NOTIFICATION_TEMPLATE_BASE_DIR.getPropertyName()
                );
                File userProvidedTemplateFile = new File(Path.of(templateBaseDir.getPropertyValue(), publisher.getPublisherTemplateFile()).toUri());
                if (userProvidedTemplateFile.exists()) {
                    templateFile = userProvidedTemplateFile;
                }
            }
            final String templateContent = FileUtils.readFileToString(templateFile, UTF_8);
            final NotificationPublisher existingPublisher = qm.getDefaultNotificationPublisher(publisher.getPublisherClass());
            if (existingPublisher == null) {
                qm.createNotificationPublisher(
                        publisher.getPublisherName(), publisher.getPublisherDescription(),
                        publisher.getPublisherClass(), templateContent, publisher.getTemplateMimeType(),
                        publisher.isDefaultPublisher()
                );
            } else {
                existingPublisher.setName(publisher.getPublisherName());
                existingPublisher.setDescription(publisher.getPublisherDescription());
                existingPublisher.setPublisherClass(publisher.getPublisherClass().getCanonicalName());
                existingPublisher.setTemplate(templateContent);
                existingPublisher.setTemplateMimeType(publisher.getTemplateMimeType());
                existingPublisher.setDefaultPublisher(publisher.isDefaultPublisher());
                qm.updateNotificationPublisher(existingPublisher);
            }
        }
    }

    private static String generateNotificationContent(final Vulnerability vulnerability) {
        final String content;
        if (vulnerability.getDescription() != null) {
            content = vulnerability.getDescription();
        } else {
            content = (vulnerability.getTitle() != null) ? vulnerability.getVulnId() + ": " +vulnerability.getTitle() : vulnerability.getVulnId();
        }
        return content;
    }

    private static String generateNotificationContent(final PolicyViolation policyViolation) {
        return "A " + policyViolation.getType().name().toLowerCase() + " policy violation occurred";
    }

    private static String generateNotificationContent(final Component component, final List<Vulnerability> vulnerabilities) {
        final String content;
        if (vulnerabilities.size() == 1) {
            content = "A dependency was introduced that contains 1 known vulnerability";
        } else {
            content = "A dependency was introduced that contains " + vulnerabilities.size() + " known vulnerabilities";
        }
        return content;
    }

    private static String generateNotificationContent(final Analysis analysis) {
        final String content;
        if (analysis.getProject() != null) {
            content = "An analysis decision was made to a finding affecting a project";
        } else {
            content = "An analysis decision was made to a finding on a component affecting all projects that have a dependency on the component";
        }
        return content;
    }

    private static String generateNotificationContent(final ViolationAnalysis violationAnalysis) {
        return "An violation analysis decision was made to a policy violation affecting a project";
    }

    public static String generateNotificationContent(final NewVulnerabilitiesSummary vo) {
        if (vo.overview().totalNewVulnerabilitiesCount() == 0) {
            return "No new vulnerabilities identified since %s.".formatted(DateUtil.toISO8601(vo.since()));
        } else {
            return "Identified %d new vulnerabilities across %d projects and %d components since %s, of which %d are suppressed.".formatted(
                    vo.overview().totalNewVulnerabilitiesCount(),
                    vo.overview().affectedProjectsCount(),
                    vo.overview().affectedComponentsCount(),
                    DateUtil.toISO8601(vo.since()),
                    vo.overview().suppressedNewVulnerabilitiesCount());
        }
    }

    public static String generateNotificationContent(final NewPolicyViolationsSummary vo) {
        if (vo.overview().totalNewViolationsCount() == 0) {
            return "No new policy violations identified since %s.".formatted(DateUtil.toISO8601(vo.since()));
        } else {
            return "Identified %d new policy violations across %d project and %d components since %s, of which %d are suppressed.".formatted(
                    vo.overview().totalNewViolationsCount(),
                    vo.overview().affectedProjectsCount(),
                    vo.overview().affectedComponentsCount(),
                    DateUtil.toISO8601(vo.since()),
                    vo.overview().suppressedNewViolationsCount());
        }
    }

    public static String generateNotificationTitle(String messageType, Project project) {
        if (project != null) {
            return messageType + " on Project: [" + project.toString() + "]";
        }
        return messageType;
    }

    public static String generateNotificationTitle(NotificationGroup notificationGroup, List<Project> projects) {
        String messageType;

        switch (notificationGroup) {
            case NEW_VULNERABILITY:
                messageType = NotificationConstants.Title.NEW_VULNERABILITY;
                break;
            case POLICY_VIOLATION:
                messageType = NotificationConstants.Title.POLICY_VIOLATION;
                break;
            default:
                return notificationGroup.name();
        }

        if (projects != null) {
            if (projects.size() == 1) {
                return generateNotificationTitle(messageType, projects.get(0));
            }
        }

        return messageType + " on " + projects.size() + " projects";
    }

    public static Object generateSubject(final NotificationRule rule, final NotificationGroup group) {
        final Project project = createProject();
        final Vulnerability vuln = createVulnerability();
        final Component component = createComponent(project);
        final Analysis analysis = createAnalysis(component, vuln);
        final PolicyViolation policyViolation = createPolicyViolation(component, project);

        return switch (group) {
            case BOM_CONSUMED, BOM_PROCESSED ->
                    new BomConsumedOrProcessed(project, "bomContent", Bom.Format.CYCLONEDX, "1.5");
            case BOM_PROCESSING_FAILED ->
                    new BomProcessingFailed(project, "bomContent", "cause", Bom.Format.CYCLONEDX, "1.5");
            case BOM_VALIDATION_FAILED ->
                    new BomValidationFailed(project, "bomContent", List.of("TEST"), Bom.Format.CYCLONEDX);
            case VEX_CONSUMED, VEX_PROCESSED -> new VexConsumedOrProcessed(project, "", Vex.Format.CYCLONEDX, "");
            case NEW_VULNERABILITY ->
                    new NewVulnerabilityIdentified(vuln, component, Set.of(project), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);
            case NEW_VULNERABLE_DEPENDENCY -> new NewVulnerableDependency(component, List.of(vuln));
            case POLICY_VIOLATION -> new PolicyViolationIdentified(policyViolation, component, project);
            case PROJECT_CREATED -> NotificationUtil.toJson(project);
            case PROJECT_AUDIT_CHANGE -> new AnalysisDecisionChange(vuln, component, project, analysis);
            case NEW_POLICY_VIOLATIONS_SUMMARY -> {
                final var projectPolicyViolation = new ProjectPolicyViolation(
                        UUID.fromString("924eaf86-454d-49f5-96c0-71d9008ac614"),
                        component,
                        policyViolation.getPolicyCondition(),
                        policyViolation.getType(),
                        policyViolation.getTimestamp(),
                        ViolationAnalysisState.APPROVED,
                        false);
                yield NewPolicyViolationsSummary.of(
                        Map.of(project, List.of(projectPolicyViolation)),
                        rule.getScheduleLastTriggeredAt(),
                        rule.getId());
            }
            case NEW_VULNERABILITIES_SUMMARY -> {
                final var projectFinding = new ProjectFinding(
                        component,
                        vuln,
                        AnalyzerIdentity.INTERNAL_ANALYZER,
                        new Date(),
                        "https://example.com",
                        analysis.getAnalysisState(),
                        analysis.isSuppressed());
                yield NewVulnerabilitiesSummary.of(
                        Map.of(project, List.of(projectFinding)),
                        rule.getScheduleLastTriggeredAt(),
                        rule.getId());
            }
            default -> null;
        };
    }

    private static Project createProject() {
        final Project project = new Project();
        project.setUuid(UUID.fromString("c9c9539a-e381-4b36-ac52-6a7ab83b2c95"));
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setPurl("pkg:maven/org.acme/projectName@projectVersion");
        return project;
    }

    private static Vulnerability createVulnerability() {
        final Vulnerability vuln = new Vulnerability();
        vuln.setUuid(UUID.fromString("bccec5d5-ec21-4958-b3e8-22a7a866a05a"));
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.MEDIUM);
        return vuln;
    }

    private static Component createComponent(Project project) {
        final Component component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("94f87321-a5d1-4c2f-b2fe-95165debebc6"));
        component.setName("componentName");
        component.setVersion("componentVersion");
        return component;
    }

    private static Analysis createAnalysis(Component component, Vulnerability vuln) {
        final Analysis analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.FALSE_POSITIVE);
        analysis.setSuppressed(true);
        return analysis;
    }

    private static PolicyViolation createPolicyViolation(Component component, Project project) {
        final Policy policy = new Policy();
        policy.setId(1);
        policy.setName("test");
        policy.setOperator(Policy.Operator.ALL);
        policy.setProjects(List.of(project));
        policy.setUuid(UUID.randomUUID());
        policy.setViolationState(Policy.ViolationState.INFO);

        final PolicyCondition condition = new PolicyCondition();
        condition.setId(1);
        condition.setUuid(UUID.randomUUID());
        condition.setOperator(Operator.NUMERIC_EQUAL);
        condition.setSubject(PolicyCondition.Subject.AGE);
        condition.setValue("1");
        condition.setPolicy(policy);

        final PolicyViolation policyViolation = new PolicyViolation();
        policyViolation.setId(1);
        policyViolation.setPolicyCondition(condition);
        policyViolation.setComponent(component);
        policyViolation.setText("test");
        policyViolation.setType(PolicyViolation.Type.SECURITY);
        policyViolation.setAnalysis(new ViolationAnalysis());
        policyViolation.setUuid(UUID.randomUUID());
        policyViolation.setTimestamp(new Date(System.currentTimeMillis()));
        return policyViolation;
    }

}
