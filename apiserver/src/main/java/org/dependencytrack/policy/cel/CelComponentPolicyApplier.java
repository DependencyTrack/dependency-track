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
package org.dependencytrack.policy.cel;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import dev.cel.common.CelValidationException;
import dev.cel.runtime.CelEvaluationException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.CreateCommentCommand;
import org.dependencytrack.persistence.jdbi.ComponentPolicyDao;
import org.dependencytrack.persistence.jdbi.ComponentPolicyDao.ComponentPolicy;
import org.dependencytrack.proto.policy.v1.Project;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Evaluates component policies (automated license curation rules) against a
 * project's components during BOM ingest, maintaining the policy-owned
 * component analyses. The first matching policy by priority wins; manual
 * analyses are never touched.
 */
public final class CelComponentPolicyApplier {

    private static final Logger LOGGER = LoggerFactory.getLogger(CelComponentPolicyApplier.class);

    private CelComponentPolicyApplier() {
    }

    public static void applyPolicies(final org.dependencytrack.model.Project project, final Collection<Component> components) {
        final long projectId = project.getId();
        if (components.isEmpty()) {
            return;
        }
        final List<ComponentPolicy> policies = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getAllEnabled());
        if (policies.isEmpty()) {
            return;
        }

        // Compile conditions, preserving priority order.
        final var compiler = CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT);
        final var programsByPolicyId = new LinkedHashMap<Long, CelPolicyProgram>();
        final var policiesById = new LinkedHashMap<Long, ComponentPolicy>();
        for (final ComponentPolicy policy : policies) {
            try {
                programsByPolicyId.put(policy.id(), compiler.compile(
                        policy.condition(), CelPolicyCompiler.CacheMode.CACHE));
                policiesById.put(policy.id(), policy);
            } catch (CelValidationException e) {
                LOGGER.warn("Failed to compile condition of component policy {}; skipping", policy.name(), e);
            }
        }
        if (programsByPolicyId.isEmpty()) {
            return;
        }

        // Protos are built from the in-flight JDO objects: at first upload the
        // project and its components are not committed yet, so reading them
        // back via JDBI would see nothing.
        final Project.Builder projectBuilder = Project.newBuilder()
                .setName(Objects.requireNonNullElse(project.getName(), ""))
                .setVersion(Objects.requireNonNullElse(project.getVersion(), ""));
        if (project.getUuid() != null) {
            projectBuilder.setUuid(project.getUuid().toString());
        }
        final Project scriptArgProject = projectBuilder.build();

        final var protoComponentsById = new java.util.HashMap<Long, org.dependencytrack.proto.policy.v1.Component>();
        for (final Component component : components) {
            final var builder = org.dependencytrack.proto.policy.v1.Component.newBuilder()
                    .setName(Objects.requireNonNullElse(component.getName(), ""));
            if (component.getUuid() != null) {
                builder.setUuid(component.getUuid().toString());
            }
            if (component.getGroup() != null) {
                builder.setGroup(component.getGroup());
            }
            if (component.getVersion() != null) {
                builder.setVersion(component.getVersion());
            }
            if (component.getPurl() != null) {
                builder.setPurl(component.getPurl().canonicalize());
            }
            if (component.getCpe() != null) {
                builder.setCpe(component.getCpe());
            }
            if (component.getSwidTagId() != null) {
                builder.setSwidTagId(component.getSwidTagId());
            }
            builder.setIsInternal(component.isInternal());
            if (component.getLicense() != null) {
                builder.setLicenseName(component.getLicense());
            }
            if (component.getLicenseExpression() != null) {
                builder.setLicenseExpression(component.getLicenseExpression());
            }
            final License resolvedLicense = component.getResolvedLicense();
            if (resolvedLicense != null) {
                final var licenseBuilder = org.dependencytrack.proto.policy.v1.License.newBuilder();
                if (resolvedLicense.getUuid() != null) {
                    licenseBuilder.setUuid(resolvedLicense.getUuid().toString());
                }
                if (resolvedLicense.getLicenseId() != null) {
                    licenseBuilder.setId(resolvedLicense.getLicenseId());
                }
                if (resolvedLicense.getName() != null) {
                    licenseBuilder.setName(resolvedLicense.getName());
                }
                builder.setResolvedLicense(licenseBuilder);
            }
            protoComponentsById.put(component.getId(), builder.build());
        }

        final Timestamp protoNow = Timestamps.now();
        int applied = 0;
        final var matchedComponentIds = new java.util.HashSet<Long>();
        for (final Component component : components) {
            final var protoComponent = protoComponentsById.getOrDefault(
                    component.getId(), org.dependencytrack.proto.policy.v1.Component.getDefaultInstance());
            for (final var entry : programsByPolicyId.entrySet()) {
                final ComponentPolicy policy = policiesById.get(entry.getKey());
                final Map<String, Object> arguments = Map.ofEntries(
                        Map.entry(CelPolicyVariable.COMPONENT.variableName(), protoComponent),
                        Map.entry(CelPolicyVariable.PROJECT.variableName(), scriptArgProject),
                        Map.entry(CelPolicyVariable.VULNS.variableName(), List.of()),
                        Map.entry(CelPolicyVariable.NOW.variableName(), protoNow));
                try {
                    if (entry.getValue().execute(arguments)) {
                        maintainAnalysis(projectId, component, policy);
                        matchedComponentIds.add(component.getId());
                        applied++;
                        break;    // first match by priority wins
                    }
                } catch (CelEvaluationException e) {
                    LOGGER.warn("Failed to evaluate condition of component policy {} for component {}",
                            policy.name(), component.getName(), e);
                    break;
                }
            }
        }
        if (applied > 0) {
            LOGGER.info("Component policies matched {} component(s) of project {}", applied, projectId);
        }

        retractStaleAnalyses(projectId, components, matchedComponentIds, policiesById);
    }

    /**
     * Clears policy-owned analyses of components no policy matches anymore
     * (e.g. the component is now imported WITH a license): the BOM-declared
     * state applies again. The analysis row and its audit trail are kept;
     * manual analyses are never touched.
     */
    private static void retractStaleAnalyses(
            final long projectId,
            final Collection<Component> components,
            final java.util.Set<Long> matchedComponentIds,
            final Map<Long, ComponentPolicy> policiesById) {
        final var unmatchedKeys = new java.util.HashMap<String, Component>();
        for (final Component component : components) {
            if (!matchedComponentIds.contains(component.getId())) {
                unmatchedKeys.put(identityKey(
                        component.getPurl() != null ? component.getPurl().canonicalize() : null,
                        component.getGroup(), component.getName(), component.getVersion()), component);
            }
        }
        if (unmatchedKeys.isEmpty()) {
            return;
        }
        inJdbiTransaction(handle -> {
            final var dao = new ComponentAnalysisDao(handle);
            for (final ComponentAnalysisDao.ComponentAnalysis analysis : dao.getAllByProject(projectId)) {
                if (analysis.policyId() == null
                        || (analysis.licenseId() == null && analysis.details() == null)) {
                    continue;
                }
                final String key = identityKey(analysis.purl(), analysis.group(),
                        analysis.name(), analysis.version());
                if (!unmatchedKeys.containsKey(key)) {
                    continue;
                }
                dao.upsertPolicyAnalysis(
                        projectId, analysis.purl(), analysis.group(),
                        analysis.name(), analysis.version(),
                        null, null, analysis.policyId());
                final ComponentPolicy policy = policiesById.get(analysis.policyId());
                final String commenter = policy != null
                        ? policyCommenter(policy)
                        : "[ComponentPolicy{Id=%d}]".formatted(analysis.policyId());
                final var comments = new java.util.ArrayList<CreateCommentCommand>();
                comments.add(new CreateCommentCommand(analysis.id(), commenter,
                        "Retracted: condition no longer matches; the imported license applies"));
                if (analysis.licenseId() != null) {
                    comments.add(new CreateCommentCommand(analysis.id(), commenter,
                            "License override: %s → not set".formatted(
                                    licenseLabel(handle, analysis.licenseId()))));
                }
                if (analysis.details() != null) {
                    comments.add(new CreateCommentCommand(analysis.id(), commenter,
                            "Details: %s → not set".formatted(analysis.details())));
                }
                dao.createComments(comments);
                LOGGER.info("Retracted component-policy analysis {} of project {}", analysis.id(), projectId);
            }
            return null;
        });
    }

    private static String policyCommenter(final ComponentPolicy policy) {
        return "[ComponentPolicy{Name=%s, Author=%s}]".formatted(
                policy.name(), Objects.requireNonNullElse(policy.author(), "?"));
    }

    /**
     * Display label of a license: its SPDX ID, or the name for custom ones.
     */
    private static String licenseLabel(final org.jdbi.v3.core.Handle handle, final Long licenseId) {
        if (licenseId == null) {
            return "not set";
        }
        return handle.createQuery("""
                        SELECT COALESCE("LICENSEID", "NAME") FROM "LICENSE" WHERE "ID" = :id
                        """)
                .bind("id", licenseId)
                .mapTo(String.class)
                .findOne()
                .orElse("unknown");
    }

    private static String identityKey(final String purl, final String group,
                                      final String name, final String version) {
        return String.join("|",
                Objects.requireNonNullElse(purl, ""),
                Objects.requireNonNullElse(group, ""),
                Objects.requireNonNullElse(name, ""),
                Objects.requireNonNullElse(version, ""));
    }

    /**
     * Creates or converges the policy-owned analysis of a matched component,
     * with audit comments on every effective change. Manual analyses win.
     */
    private static void maintainAnalysis(final long projectId, final Component component, final ComponentPolicy policy) {
        final String purl = component.getPurl() != null ? component.getPurl().canonicalize() : null;
        inJdbiTransaction(handle -> {
            final var dao = new ComponentAnalysisDao(handle);
            final ComponentAnalysisDao.ComponentAnalysis existing = dao.getByIdentity(
                    projectId, purl, component.getGroup(),
                    component.getName(), component.getVersion()).orElse(null);
            if (existing != null && existing.policyId() == null) {
                return null;    // manual analysis wins
            }
            if (existing != null
                    && Objects.equals(existing.licenseId(), policy.licenseId())
                    && Objects.equals(existing.details(), policy.details())
                    && Objects.equals(existing.policyId(), policy.id())) {
                return null;    // already converged, keep the audit trail quiet
            }
            final Long analysisId = dao.upsertPolicyAnalysis(
                    projectId, purl, component.getGroup(),
                    component.getName(), component.getVersion(),
                    policy.licenseId(), policy.details(), policy.id()).orElse(null);
            if (analysisId == null) {
                return null;    // raced by a manual analysis
            }
            final String commenter = policyCommenter(policy);
            final var comments = new java.util.ArrayList<CreateCommentCommand>();
            comments.add(new CreateCommentCommand(analysisId, commenter,
                    "Matched on condition: " + policy.condition()));
            final Long oldLicenseId = existing != null ? existing.licenseId() : null;
            if (!Objects.equals(oldLicenseId, policy.licenseId())) {
                comments.add(new CreateCommentCommand(analysisId, commenter,
                        "License override: %s → %s".formatted(
                                licenseLabel(handle, oldLicenseId),
                                licenseLabel(handle, policy.licenseId()))));
            }
            final String oldDetails = existing != null ? existing.details() : null;
            if (!Objects.equals(oldDetails, policy.details())) {
                comments.add(new CreateCommentCommand(analysisId, commenter,
                        "Details: %s → %s".formatted(
                                Objects.requireNonNullElse(oldDetails, "not set"),
                                Objects.requireNonNullElse(policy.details(), "not set"))));
            }
            dao.createComments(comments);
            return null;
        });
    }
}
