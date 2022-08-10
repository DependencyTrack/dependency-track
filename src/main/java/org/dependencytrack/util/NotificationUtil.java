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
package org.dependencytrack.util;

import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.FileUtils;
import org.dependencytrack.model.*;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.FetchPlan;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class NotificationUtil {

    /**
     * Private constructor.
     */
    private NotificationUtil() { }

    public static void analyzeNotificationCriteria(QueryManager qm, Vulnerability vulnerability, Component component) {
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
            final Component detachedComponent = qm.detach(Component.class, component.getId());

            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.NEW_VULNERABILITY)
                    .title(NotificationConstants.Title.NEW_VULNERABILITY)
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(detachedVuln))
                    .subject(new NewVulnerabilityIdentified(detachedVuln, detachedComponent, new HashSet<>(affectedProjects.values())))
            );
        }
    }
/*
    public static void analyzeNotificationCriteria(final QueryManager qm, final Dependency newDependency) {
        Dependency dependency = qm.getDependency(newDependency);
        final List<Vulnerability> vulnerabilities = qm.detach(qm.getAllVulnerabilities(dependency));
        dependency = qm.detach(Dependency.class, dependency.getId());
        for (final Vulnerability vulnerability: vulnerabilities) {
            final Set<Project> affectedProjects = new HashSet<>(Collections.singletonList(dependency.getProject()));
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.NEW_VULNERABILITY)
                    .title(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY)
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(vulnerability))
                    .subject(new NewVulnerabilityIdentified(vulnerability, dependency.getComponent(), affectedProjects))
            );
        }
        if (CollectionUtils.isNotEmpty(vulnerabilities)) {
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.NEW_VULNERABLE_DEPENDENCY)
                    .title(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY)
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(dependency, vulnerabilities))
                    .subject(new NewVulnerableDependency(dependency, vulnerabilities))
            );
        }
    }
*/
    public static void analyzeNotificationCriteria(final QueryManager qm, Analysis analysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            final Set<Project> affectedProjects = new HashSet<>();
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;
            affectedProjects.add(analysis.getProject());

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

            analysis = qm.detach(Analysis.class, analysis.getId());
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(title)
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(analysis))
                    .subject(new AnalysisDecisionChange(analysis.getVulnerability(),
                            analysis.getComponent(), affectedProjects, analysis))
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

            violationAnalysis = qm.detach(ViolationAnalysis.class, violationAnalysis.getId());
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(title)
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
                .title(NotificationConstants.Title.POLICY_VIOLATION)
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
        JsonUtil.add(vulnerabilityBuilder, "title", vulnerability.getTitle());
        JsonUtil.add(vulnerabilityBuilder, "subtitle", vulnerability.getSubTitle());
        JsonUtil.add(vulnerabilityBuilder, "description", vulnerability.getDescription());
        JsonUtil.add(vulnerabilityBuilder, "recommendation", vulnerability.getRecommendation());
        JsonUtil.add(vulnerabilityBuilder, "cvssv2", vulnerability.getCvssV2BaseScore());
        JsonUtil.add(vulnerabilityBuilder, "cvssv3", vulnerability.getCvssV3BaseScore());
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

    public static JsonObject toJson(final NewVulnerabilityIdentified vo) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (vo.getComponent() != null) {
            builder.add("component", toJson(vo.getComponent()));
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
        if (vo.getAffectedProjects() != null && vo.getAffectedProjects().size() > 0) {
            final JsonArrayBuilder projectsBuilder = Json.createArrayBuilder();
            for (final Project project: vo.getAffectedProjects()) {
                projectsBuilder.add(toJson(project));
            }
            builder.add("affectedProjects", projectsBuilder.build());
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
}
