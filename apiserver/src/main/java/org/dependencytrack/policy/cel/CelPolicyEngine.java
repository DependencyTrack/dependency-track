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
import dev.cel.common.types.CelType;
import dev.cel.runtime.CelEvaluationException;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.policy.cel.CelPolicyCompiler.CacheMode;
import org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.ComponentAgeCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.ComponentHashCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CoordinatesCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CpeCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CweCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.EpssCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.InternalStatusCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.LicenseCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.LicenseGroupCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.PackageUrlCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.SeverityCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.SwidTagIdCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.VersionCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.VersionDistanceCelScriptBuilder;
import org.dependencytrack.policy.cel.compat.VulnerabilityIdCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.persistence.CelPolicyDao;
import org.dependencytrack.policy.cel.persistence.CelPolicyDao.ComponentWithLicenseId;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import static org.apache.commons.collections4.MultiMapUtils.emptyMultiValuedMap;
import static org.dependencytrack.notification.api.NotificationFactory.createPolicyViolationNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_COMPONENT_PROPERTY;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyTypes.TYPE_VULNERABILITY;

public final class CelPolicyEngine {

    private static final Logger LOGGER = LoggerFactory.getLogger(CelPolicyEngine.class);
    private static final Map<Subject, CelPolicyScriptSourceBuilder> SCRIPT_BUILDERS = Map.ofEntries(
            Map.entry(Subject.AGE, new ComponentAgeCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.COMPONENT_HASH, new ComponentHashCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.COORDINATES, new CoordinatesCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.CPE, new CpeCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.CWE, new CweCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.EPSS, new EpssCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.EXPRESSION, PolicyCondition::getValue),
            Map.entry(Subject.IS_INTERNAL, new InternalStatusCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.LICENSE, new LicenseCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.LICENSE_GROUP, new LicenseGroupCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.PACKAGE_URL, new PackageUrlCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.SEVERITY, new SeverityCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.SWID_TAGID, new SwidTagIdCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.VERSION, new VersionCelPolicyScriptSourceBuilder()),
            Map.entry(Subject.VERSION_DISTANCE, new VersionDistanceCelScriptBuilder()),
            Map.entry(Subject.VULNERABILITY_ID, new VulnerabilityIdCelPolicyScriptSourceBuilder()));

    private final CelPolicyCompiler scriptHost;

    public CelPolicyEngine() {
        this(CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT));
    }

    CelPolicyEngine(final CelPolicyCompiler scriptHost) {
        this.scriptHost = scriptHost;
    }

    public void evaluateProject(UUID uuid) {
        // TODO: Should this entire procedure run in a single DB transaction?
        //   Would be better for atomicity, but could block DB connections for prolonged
        //   period of time for larger projects with many violations.

        final Long projectId = withJdbiHandle(
                handle -> handle.attach(ProjectDao.class).getProjectId(uuid));
        if (projectId == null) {
            LOGGER.warn("Project does not exist; Skipping");
            return;
        }

        LOGGER.debug("Fetching applicable policies");
        final List<Policy> applicablePolicies = withJdbiHandle(
                handle -> new CelPolicyDao(handle).getApplicablePolicies(projectId));
        if (applicablePolicies.isEmpty()) {
            LOGGER.info("No applicable policies found");
            inJdbiTransaction(handle ->
                    new CelPolicyDao(handle).reconcileViolations(
                            projectId, emptyMultiValuedMap()));
            return;
        }

        LOGGER.debug("Compiling policy scripts");
        final List<PolicyWithScripts> policiesWithScripts =
                compilePoliciesScripts(applicablePolicies);
        if (policiesWithScripts.isEmpty()) {
            LOGGER.info("No compilable policy conditions found");
            inJdbiTransaction(handle ->
                    new CelPolicyDao(handle).reconcileViolations(
                            projectId, emptyMultiValuedMap()));
            return;
        }

        final MultiValuedMap<CelType, String> requirements = determineScriptRequirements(policiesWithScripts);
        final long conditionCount = policiesWithScripts.stream().mapToLong(pws -> pws.conditionScripts().size()).sum();
        LOGGER.debug("Requirements for {} policy conditions: {}", conditionCount, requirements);

        final Project protoProject;
        if (requirements.containsKey(TYPE_PROJECT)) {
            protoProject = withJdbiHandle(handle ->
                    new CelPolicyDao(handle)
                            .loadRequiredFields(projectId, requirements));
        } else {
            protoProject = Project.getDefaultInstance();
        }

        // Preload components for the entire project, to avoid excessive queries.
        final Map<Long, ComponentWithLicenseId> componentsWithLicense = withJdbiHandle(
                handle -> new CelPolicyDao(handle)
                        .fetchAllComponents(projectId, requirements.get(TYPE_COMPONENT)));

        // Preload licenses for the entire project, as chances are high that
        // they will be used by multiple components.
        final Map<Long, License> licenseById;
        if (requirements.containsKey(TYPE_LICENSE)
                || (requirements.containsKey(TYPE_COMPONENT) && requirements.get(TYPE_COMPONENT).contains("resolved_license"))) {
            licenseById = withJdbiHandle(
                    handle -> new CelPolicyDao(handle)
                            .fetchAllLicenses(
                                    projectId,
                                    requirements.get(TYPE_LICENSE),
                                    requirements.get(TYPE_LICENSE_GROUP)));
        } else {
            licenseById = Collections.emptyMap();
        }

        // Preload component properties for the entire project.
        final Map<Long, List<Component.Property>> componentPropertiesById;
        if (requirements.containsKey(TYPE_COMPONENT)
                && requirements.get(TYPE_COMPONENT).contains("properties")) {
            componentPropertiesById = withJdbiHandle(
                    handle -> new CelPolicyDao(handle)
                            .fetchAllComponentProperties(
                                    projectId,
                                    requirements.get(TYPE_COMPONENT_PROPERTY)));
        } else {
            componentPropertiesById = Collections.emptyMap();
        }

        // Build final component protos, enriching with resolved licenses and properties where applicable.
        final var componentsById = new HashMap<Long, Component>();
        for (final var entry : componentsWithLicense.entrySet()) {
            final long componentId = entry.getKey();
            final ComponentWithLicenseId cwl = entry.getValue();

            final Component.Builder componentBuilder = cwl.component().toBuilder();

            if (cwl.resolvedLicenseId() != null && cwl.resolvedLicenseId() > 0) {
                final License license = licenseById.get(cwl.resolvedLicenseId());
                if (license != null) {
                    componentBuilder.setResolvedLicense(license);
                } else {
                    LOGGER.warn("""
                            Component with DB ID {} refers to license with ID {}, \
                            but no license with that ID was found""", componentId, cwl.resolvedLicenseId());
                }
            }

            final List<Component.Property> properties = componentPropertiesById.get(componentId);
            if (properties != null && !properties.isEmpty()) {
                componentBuilder.addAllProperties(properties);
            }

            componentsById.put(componentId, componentBuilder.build());
        }

        // Preload vulnerabilities for the entire project,
        // as chances are high that they will be used by multiple components.
        final Map<Long, Vulnerability> protoVulnById;
        final Map<Long, Set<Long>> vulnIdsByComponentId;
        if (requirements.containsKey(TYPE_VULNERABILITY)) {
            protoVulnById = withJdbiHandle(handle ->
                    new CelPolicyDao(handle)
                            .fetchAllVulnerabilities(
                                    projectId,
                                    requirements.get(TYPE_VULNERABILITY)));

            vulnIdsByComponentId = withJdbiHandle(handle ->
                    new CelPolicyDao(handle)
                            .fetchAllComponentsVulnerabilities(projectId));
        } else {
            protoVulnById = Collections.emptyMap();
            vulnIdsByComponentId = Collections.emptyMap();
        }

        final var violationsByComponentId = new ArrayListValuedHashMap<Long, PolicyViolation>();
        final Timestamp protoNow = Timestamps.now();

        for (final Map.Entry<Long, Component> entry : componentsById.entrySet()) {
            final long componentId = entry.getKey();
            final Component protoComponent = entry.getValue();

            final List<Vulnerability> protoVulns;
            if (requirements.containsKey(TYPE_VULNERABILITY)) {
                protoVulns = vulnIdsByComponentId.getOrDefault(componentId, Set.of()).stream()
                        .map(protoVulnById::get)
                        .filter(Objects::nonNull)
                        .toList();
            } else {
                protoVulns = List.of();
            }

            evaluateComponentAgainstPolicies(
                    policiesWithScripts,
                    componentId,
                    Map.ofEntries(
                            Map.entry(CelPolicyVariable.COMPONENT.variableName(), protoComponent),
                            Map.entry(CelPolicyVariable.PROJECT.variableName(), protoProject),
                            Map.entry(CelPolicyVariable.VULNS.variableName(), protoVulns),
                            Map.entry(CelPolicyVariable.NOW.variableName(), protoNow)),
                    violationsByComponentId);
        }

        final Set<Long> newViolationIds = inJdbiTransaction(handle ->
                new CelPolicyDao(handle).reconcileViolations(
                        projectId, violationsByComponentId));
        LOGGER.info("Identified {} new violations", newViolationIds.size());

        if (!newViolationIds.isEmpty()) {
            useJdbiTransaction(handle -> new JdbiNotificationEmitter(handle).emitAll(
                    handle.attach(NotificationSubjectDao.class)
                            .getForNewPolicyViolations(newViolationIds)
                            .stream()
                            .map(subject -> createPolicyViolationNotification(
                                    subject.getProject(), subject.getComponent(), subject.getPolicyViolation()))
                            .toList()));
        }
    }

    record ConditionScript(PolicyCondition condition, CelPolicyProgram script) {
    }

    record PolicyWithScripts(Policy policy, List<ConditionScript> conditionScripts) {
    }

    private List<PolicyWithScripts> compilePoliciesScripts(List<Policy> policies) {
        final var result = new ArrayList<PolicyWithScripts>();
        for (final Policy policy : policies) {
            final var conditionScripts = new ArrayList<ConditionScript>();

            for (final PolicyCondition condition : policy.getPolicyConditions()) {
                final CelPolicyProgram script = compileCondition(condition);
                if (script != null) {
                    conditionScripts.add(new ConditionScript(condition, script));
                }
            }

            if (!conditionScripts.isEmpty()) {
                result.add(new PolicyWithScripts(policy, conditionScripts));
            }
        }

        return result;
    }

    private MultiValuedMap<CelType, String> determineScriptRequirements(
            Collection<PolicyWithScripts> policiesWithScripts) {
        final var requirements = new HashSetValuedHashMap<CelType, String>();

        for (final PolicyWithScripts policyWithScripts : policiesWithScripts) {
            for (final ConditionScript conditionScript : policyWithScripts.conditionScripts()) {
                requirements.putAll(conditionScript.script().getRequirements());
            }
        }

        return requirements;
    }

    private CelPolicyProgram compileCondition(PolicyCondition policyCondition) {
        final CelPolicyScriptSourceBuilder scriptBuilder = SCRIPT_BUILDERS.get(policyCondition.getSubject());
        if (scriptBuilder == null) {
            LOGGER.warn("""
                    No script builder found that is capable of handling subjects of type {};\
                    Condition will be skipped""", policyCondition.getSubject());
            return null;
        }

        final String scriptSrc = scriptBuilder.apply(policyCondition);
        if (scriptSrc == null) {
            LOGGER.warn(
                    "Unable to create CEL script for condition {}; Condition will be skipped",
                    policyCondition.getUuid());
            return null;
        }

        try {
            return scriptHost.compile(scriptSrc, CacheMode.CACHE);
        } catch (CelValidationException e) {
            LOGGER.warn(
                    "Failed to compile script for condition {}; Condition will be skipped",
                    policyCondition.getUuid(), e);
            return null;
        }
    }

    private void evaluateComponentAgainstPolicies(
            List<PolicyWithScripts> policiesWithScripts,
            long componentId,
            Map<String, Object> scriptArgs,
            MultiValuedMap<Long, PolicyViolation> violationsByComponentId) {
        for (final PolicyWithScripts pws : policiesWithScripts) {
            final Policy policy = pws.policy();
            final var violatedConditions = new ArrayList<PolicyCondition>();

            for (final ConditionScript cs : pws.conditionScripts()) {
                try {
                    if (cs.script().execute(scriptArgs)) {
                        violatedConditions.add(cs.condition());
                    }
                } catch (CelEvaluationException e) {
                    LOGGER.warn("Failed to execute script for condition {}", cs.condition().getUuid(), e);
                }
            }

            final boolean policyViolated = switch (policy.getOperator()) {
                case ANY -> !violatedConditions.isEmpty();
                case ALL -> violatedConditions.size() == policy.getPolicyConditions().size();
            };

            if (policyViolated) {
                for (final PolicyCondition condition : violatedConditions) {
                    final var violation = new PolicyViolation();
                    violation.setType(condition.getViolationType());
                    violation.setPolicyCondition(condition);
                    violation.setTimestamp(new Date());
                    violationsByComponentId.put(componentId, violation);
                }
            }
        }
    }

}
