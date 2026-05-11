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
package org.dependencytrack.persistence;

import alpine.model.ApiKey;
import alpine.model.User;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.util.DateUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.dependencytrack.notification.api.NotificationFactory.createPolicyViolationAnalysisDecisionChangeNotification;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistentAll;

final class PolicyQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    PolicyQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    PolicyQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a List of all Policy objects.
     * @return a List of all Policy objects
     */
    public PaginatedResult getPolicies() {
        final Query<Policy> query = pm.newQuery(Policy.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a policy by it's name.
     * @param name the name of the policy (required)
     * @return a Policy object, or null if not found
     */
    public Policy getPolicy(final String name) {
        final Query<Policy> query = pm.newQuery(Policy.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new Policy.
     * @param name the name of the policy to create
     * @param operator the operator
     * @param violationState the violation state
     * @return the created Policy
     */
    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState,
                               boolean onlyLatestProjectVersion) {
        final Policy policy = new Policy();
        policy.setName(name);
        policy.setOperator(operator);
        policy.setViolationState(violationState);
        policy.setOnlyLatestProjectVersion(onlyLatestProjectVersion);
        return persist(policy);
    }

    /**
     * Creates a policy condition for the specified Project.
     * @return the created PolicyCondition object
     */
    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        return createPolicyCondition(policy, subject, operator, value, null);
    }

    /**
     * Creates a policy condition for the specified Project.
     * @return the created PolicyCondition object
     */
    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value,
                                                 final PolicyViolation.Type violationType) {
        final PolicyCondition pc = new PolicyCondition();
        pc.setPolicy(policy);
        pc.setSubject(subject);
        if (subject == PolicyCondition.Subject.EXPRESSION) {
            pc.setOperator(PolicyCondition.Operator.MATCHES);
        } else {
            pc.setOperator(operator);
        }
        pc.setValue(value);
        pc.setViolationType(violationType);
        return persist(pc);
    }

    /**
     * Updates a policy condition.
     * @return the updated PolicyCondition object
     */
    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        final PolicyCondition pc = getObjectByUuid(PolicyCondition.class, policyCondition.getUuid());
        pc.setSubject(policyCondition.getSubject());
        if (policyCondition.getSubject() == PolicyCondition.Subject.EXPRESSION) {
            pc.setOperator(PolicyCondition.Operator.MATCHES);
        } else {
            pc.setOperator(policyCondition.getOperator());
        }
        pc.setValue(policyCondition.getValue());
        pc.setViolationType(policyCondition.getViolationType());
        return persist(pc);
    }

    /**
     * Returns a List of all {@link PolicyViolation}s for a specific component.
     * @param component The component to fetch {@link PolicyViolation}s for
     * @return a List of {@link PolicyViolation}s
     */
    public List<PolicyViolation> getAllPolicyViolations(final Component component) {
        return getAllPolicyViolations(component, true);
    }

    /**
     * Returns a List of all {@link PolicyViolation}s for a specific component.
     * @param component The component to fetch {@link PolicyViolation}s for
     * @param includeSuppressed Whether to include suppressed violations or not
     * @return a List of {@link PolicyViolation}s
     */
    public List<PolicyViolation> getAllPolicyViolations(final Component component, final boolean includeSuppressed) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (includeSuppressed) {
            query.setFilter("component.id == :cid");
        } else {
            query.setFilter("component.id == :cid && suppressions == 0");
            query.declareVariables("long suppressions");

            // For a given policy violation, check whether an analysis exists that suppresses it.
            // The query will return either 0 (no analysis exists or not suppressed) or 1 (suppressed).
            final Query<ViolationAnalysis> subQuery = pm.newQuery(ViolationAnalysis.class);
            subQuery.setFilter("policyViolation == :policyViolation && suppressed == true");
            subQuery.setResult("count(id)");
            query.addSubquery(subQuery, "long suppressions", null, "this");
        }
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        query.setParameters(component.getId());
        return query.executeList();
    }

    /**
     * Returns a List of all Policy objects for a specific component.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final Project project) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "project.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(project.getId());
    }

    /**
     * Returns a List of all Policy violations for a specific project.
     * @param project the project to retrieve violations for
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(final Project project, boolean includeSuppressed) {
        PaginatedResult result;
        final String queryFilter = includeSuppressed ? "project.id == :pid" : "project.id == :pid && (analysis.suppressed == false || analysis.suppressed == null)";
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        if (filter != null) {
            query.setFilter(queryFilter + " && (policyCondition.policy.name.toLowerCase().matches(:filter) || component.name.toLowerCase().matches(:filter))");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, project.getId(), filterString);
        } else {
            query.setFilter(queryFilter);
            result = execute(query, project.getId());
        }
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
            violation.setAnalysis(getViolationAnalysis(violation.getComponent(), violation)); // Include the violation analysis by default
        }
        return result;
    }

    /**
     * Returns a List of all Policy violations for a specific component.
     * @param component the component to retrieve violations for
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(final Component component, boolean includeSuppressed) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (includeSuppressed) {
            query.setFilter("component.id == :cid");
        } else {
            query.setFilter("component.id == :cid && (analysis.suppressed == false || analysis.suppressed == null)");
        }
        if (orderBy == null) {
            query.setOrdering("timestamp desc");
        }
        final PaginatedResult result = execute(query, component.getId());
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
            violation.setAnalysis(getViolationAnalysis(violation.getComponent(), violation)); // Include the violation analysis by default
        }
        return result;
    }

    /**
     * Returns a List of all Policy violations for the entire portfolio filtered by ACL and other optional filters.
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(boolean includeSuppressed, boolean showInactive, Map<String, String> filters) {
        final PaginatedResult result;
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        final Map<String, Object> params = new HashMap<>();
        final List<String> filterCriteria = new ArrayList<>();
        if (!includeSuppressed) {
            filterCriteria.add("(analysis.suppressed == false || analysis.suppressed == null)");
        }
        if (!showInactive) {
            filterCriteria.add("(project.inactiveSince == null)");
        }
        processViolationsFilters(filters, params, filterCriteria);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        final String queryFilter = String.join(" && ", filterCriteria);
        preprocessACLs(query, queryFilter, params);
        result = execute(query, params);
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to be included since it's not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to be included since it's not the default
            violation.setAnalysis(getViolationAnalysis(violation.getComponent(), violation)); // Include the violation analysis by default
        }
        return result;
    }

    /**
     * Returns a ViolationAnalysis for the specified Component and PolicyViolation.
     * @param component the Component
     * @param policyViolation the PolicyViolation
     * @return a ViolationAnalysis object, or null if not found
     */
    public ViolationAnalysis getViolationAnalysis(Component component, PolicyViolation policyViolation) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "component == :component && policyViolation == :policyViolation");
        query.setRange(0, 1);
        return singleResult(query.execute(component, policyViolation));
    }

    /**
     * @since 5.0.0
     */
    public long makeViolationAnalysis(final MakeViolationAnalysisCommand command) {
        assertPersistent(command.component(), "component must be persistent");
        assertPersistent(command.violation(), "violation must be persistent");

        return callInTransaction(() -> {
            ViolationAnalysis analysis = getViolationAnalysis(command.component(), command.violation());
            if (analysis == null) {
                analysis = new ViolationAnalysis();
                analysis.setComponent(command.component());
                analysis.setPolicyViolation(command.violation());
                analysis.setViolationAnalysisState(ViolationAnalysisState.NOT_SET);
                analysis.setSuppressed(false);
                persist(analysis);
            }

            boolean stateChanged = false;
            boolean suppressionChanged = false;
            final var auditTrailComments = new ArrayList<String>();

            if (command.state() != null && command.state() != analysis.getAnalysisState()) {
                auditTrailComments.add("%s → %s".formatted(analysis.getAnalysisState(), command.state()));
                analysis.setViolationAnalysisState(command.state());
                stateChanged = true;
            }
            if (command.suppress() != null && command.suppress() != analysis.isSuppressed()) {
                auditTrailComments.add(command.suppress() ? "Suppressed" : "Unsuppressed");
                analysis.setSuppressed(command.suppress());
                suppressionChanged = true;
            }

            final List<String> comments =
                    !command.options().contains(MakeViolationAnalysisCommand.Option.OMIT_AUDIT_TRAIL)
                            ? auditTrailComments
                            : new ArrayList<>();
            if (command.comment() != null) {
                comments.add(command.comment());
            }

            createViolationAnalysisComments(analysis, command.commenter(), comments);

            if (!command.options().contains(MakeViolationAnalysisCommand.Option.OMIT_NOTIFICATION)
                    && (stateChanged || suppressionChanged)) {
                new JdoNotificationEmitter(this).emit(
                        createPolicyViolationAnalysisDecisionChangeNotification(
                                NotificationModelConverter.convert(analysis.getProject()),
                                NotificationModelConverter.convert(analysis.getComponent()),
                                NotificationModelConverter.convert(analysis.getPolicyViolation()),
                                NotificationModelConverter.convert(analysis),
                                stateChanged,
                                suppressionChanged));
            }

            return analysis.getId();
        });
    }

    private void createViolationAnalysisComments(
            final ViolationAnalysis analysis,
            final String commenter,
            final List<String> comments) {
        assertPersistent(analysis, "analysis must be persistent");

        if (comments == null || comments.isEmpty()) {
            return;
        }

        final var now = new Date();

        final String commenterToUse;
        if (commenter == null) {
            commenterToUse = switch (principal) {
                case User user -> user.getUsername();
                case ApiKey apiKey -> apiKey.getTeams().get(0).getName();
                case null -> null;
                default -> throw new IllegalStateException(
                        "Unexpected principal type: " + principal.getClass().getName());
            };
        } else {
            commenterToUse = commenter;
        }

        runInTransaction(() -> {
            final var analysisComments = new ArrayList<ViolationAnalysisComment>(comments.size());

            for (final String comment : comments) {
                final var analysisComment = new ViolationAnalysisComment();
                analysisComment.setViolationAnalysis(analysis);
                analysisComment.setCommenter(commenterToUse);
                analysisComment.setComment(comment);
                analysisComment.setTimestamp(now);
                analysisComments.add(analysisComment);
            }

            persist(analysisComments);

            if (analysis.getAnalysisComments() != null) {
                analysis.getAnalysisComments().addAll(analysisComments);
            } else {
                analysis.setAnalysisComments(analysisComments);
            }
        });
    }

    /**
     * Returns a List of all LicenseGroup objects.
     * @return a List of all LicenseGroup objects
     */
    public PaginatedResult getLicenseGroups() {
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a license group by it's name.
     * @param name the name of the license group (required)
     * @return a LicenseGroup object, or null if not found
     */
    public LicenseGroup getLicenseGroup(final String name) {
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new LicenseGroup.
     * @param name the name of the license group to create
     * @return the created LicenseGroup
     */
    public LicenseGroup createLicenseGroup(String name) {
        final LicenseGroup licenseGroup = new LicenseGroup();
        licenseGroup.setName(name);
        return persist(licenseGroup);
    }

    /**
     * @since 4.12.3
     */
    @Override
    public boolean bind(final Policy policy, final Collection<Tag> tags, final boolean keepExisting) {
        assertPersistent(policy, "policy must be persistent");
        assertPersistentAll(tags, "tags must be persistent");
        return callInTransaction(() -> {
            boolean modified = false;

            if (policy.getTags() == null) {
                policy.setTags(new HashSet<>());
            }

            if (!keepExisting) {
                final Iterator<Tag> existingTagsIterator = policy.getTags().iterator();
                while (existingTagsIterator.hasNext()) {
                    final Tag existingTag = existingTagsIterator.next();
                    if (!tags.contains(existingTag)) {
                        existingTagsIterator.remove();
                        if (existingTag.getPolicies() != null) {
                            existingTag.getPolicies().remove(policy);
                        }
                        modified = true;
                    }
                }
            }

            for (final Tag tag : tags) {
                if (!policy.getTags().contains(tag)) {
                    policy.getTags().add(tag);
                    if (tag.getPolicies() == null) {
                        tag.setPolicies(new HashSet<>(Set.of(policy)));
                    } else {
                        tag.getPolicies().add(policy);
                    }
                    modified = true;
                }
            }
            return modified;
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public boolean bind(final Policy policy, final Collection<Tag> tags) {
        return bind(policy, tags, /* keepExisting */ false);
    }

    private void processViolationsFilters(Map<String, String> filters, Map<String, Object> params, List<String> filterCriteria) {
        for (Map.Entry<String, String> filter : filters.entrySet()) {
            switch (filter.getKey()) {
                case "violationState" -> processArrayFilter(params, filterCriteria, "violationState", filter.getValue(), "policyCondition.policy.violationState");
                case "riskType" -> processArrayFilter(params, filterCriteria, "riskType", filter.getValue(), "type");
                case "policy" -> processArrayFilter(params, filterCriteria, "policy", filter.getValue(), "policyCondition.policy.uuid");
                case "analysisState" -> processArrayFilter(params, filterCriteria, "analysisState", filter.getValue(), "analysis.analysisState");
                case "occurredOnDateFrom" -> processDateFilter(params, filterCriteria, "occuredOnDateFrom", filter.getValue(), true);
                case "occurredOnDateTo" -> processDateFilter(params, filterCriteria, "occuredOnDateTo", filter.getValue(), false);
                case "textSearchField" -> processInputFilter(params, filterCriteria, "textInput", filter.getValue(), filters.get("textSearchInput"));
            }
        }
    }

    private void processArrayFilter(Map<String, Object> params, List<String> filterCriteria, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            StringBuilder filterBuilder = new StringBuilder("(");
            String[] arrayFilter = filter.split(",");
            for (int i = 0, arrayFilterLength = arrayFilter.length; i < arrayFilterLength; i++) {
                filterBuilder.append(column).append(" == :").append(paramName).append(i);
                switch (paramName) {
                    case "violationState" -> params.put(paramName + i, Policy.ViolationState.valueOf(arrayFilter[i]));
                    case "riskType" -> params.put(paramName + i, PolicyViolation.Type.valueOf(arrayFilter[i]));
                    case "policy" -> params.put(paramName + i, UUID.fromString(arrayFilter[i]));
                    case "analysisState" -> {
                        if (arrayFilter[i].equals("NOT_SET")) {
                            filterBuilder.append(" || ").append(column).append(" == null");
                        }
                        params.put(paramName + i, ViolationAnalysisState.valueOf(arrayFilter[i]));
                    }
                }
                if (i < arrayFilterLength - 1) {
                    filterBuilder.append(" || ");
                }
            }
            filterBuilder.append(")");
            filterCriteria.add(filterBuilder.toString());
        }
    }

    private void processDateFilter(Map<String, Object> params, List<String> filterCriteria, String paramName, String filter, boolean fromValue) {
        if (filter != null && !filter.isEmpty()) {
            params.put(paramName, DateUtil.fromISO8601(filter + (fromValue ? "T00:00:00" : "T23:59:59")));
            filterCriteria.add("(timestamp " + (fromValue ? ">= :" : "<= :") + paramName + ")");
        }
    }

    private void processInputFilter(Map<String, Object> params, List<String> filterCriteria, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            StringBuilder filterBuilder = new StringBuilder("(");
            String[] inputFilter = filter.split(",");
            for (int i = 0, inputFilterLength = inputFilter.length; i < inputFilterLength; i++) {
                switch (inputFilter[i].toLowerCase()) {
                    case "policy_name" -> filterBuilder.append("policyCondition.policy.name");
                    case "component" -> filterBuilder.append("component.name");
                    case "license" -> filterBuilder.append("component.resolvedLicense.licenseId.toLowerCase().matches(:").append(paramName).append(") || component.license");
                    case "project_name" -> filterBuilder.append("project.name.toLowerCase().matches(:").append(paramName).append(") || project.version");
                }
                filterBuilder.append(".toLowerCase().matches(:").append(paramName).append(")");
                if (i < inputFilterLength - 1) {
                    filterBuilder.append(" || ");
                }
            }
            params.put(paramName, ".*" + input.toLowerCase() + ".*");
            filterBuilder.append(")");
            filterCriteria.add(filterBuilder.toString());
        }
    }

}
