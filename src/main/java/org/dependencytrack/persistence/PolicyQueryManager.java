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
package org.dependencytrack.persistence;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    public List<Policy> getAllPolicies() {
        final Query<Policy> query = pm.newQuery(Policy.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        return query.executeList();
    }

    /**
     * Returns a policy by it's name.
     * @param name the name of the policy (required)
     * @return a Policy object, or null if not found
     */
    public Policy getPolicy(final String name) {
        final Query<Policy> query = pm.newQuery(Policy.class, "name == :name");
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new Policy.
     * @param name the name of the policy to create
     * @param operator the operator
     * @param violationState the violation state
     * @return the created Policy
     */
    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState) {
        final Policy policy = new Policy();
        policy.setName(name);
        policy.setOperator(operator);
        policy.setViolationState(violationState);
        return persist(policy);
    }

    /**
     * Creates a policy condition for the specified Project.
     * @return the created PolicyCondition object
     */
    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        final PolicyCondition pc = new PolicyCondition();
        pc.setPolicy(policy);
        pc.setSubject(subject);
        pc.setOperator(operator);
        pc.setValue(value);
        return persist(pc);
    }

    /**
     * Updates a policy condition.
     * @return the updated PolicyCondition object
     */
    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        final PolicyCondition pc = getObjectByUuid(PolicyCondition.class, policyCondition.getUuid());
        pc.setSubject(policyCondition.getSubject());
        pc.setOperator(policyCondition.getOperator());
        pc.setValue(policyCondition.getValue());
        return persist(pc);
    }

    /**
     * Intelligently adds dependencies for components that are not already a dependency
     * of the specified project and removes the dependency relationship for components
     * that are not in the list of specified components.
     * @param component the project to bind components to
     * @param policyViolations the complete list of existing dependent components
     */
    public synchronized void reconcilePolicyViolations(final Component component, final List<PolicyViolation> policyViolations) {
        // Removes violations as dependencies to the project for all
        // components not included in the list provided
        List<PolicyViolation> markedForDeletion = new ArrayList<>();
        for (final PolicyViolation existingViolation: getAllPolicyViolations(component)) {
            boolean keep = false;
            for (final PolicyViolation violation: policyViolations) {
                if (violation.getType() == existingViolation.getType()
                        && violation.getPolicyCondition().getId() == existingViolation.getPolicyCondition().getId()
                        && violation.getComponent().getId() == existingViolation.getComponent().getId())
                {
                    keep = true;
                    break;
                }
            }
            if (!keep) {
                markedForDeletion.add(existingViolation);
            }
        }
        if (!markedForDeletion.isEmpty()) {
            delete(markedForDeletion);
        }
    }

    /**
     * Adds a policy violation
     * @param pv the policy violation to add
     */
    public synchronized PolicyViolation addPolicyViolationIfNotExist(final PolicyViolation pv) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "type == :type && component == :component && policyCondition == :policyCondition");
        PolicyViolation result = singleResult(query.execute(pv.getType(), pv.getComponent(), pv.getPolicyCondition()));
        if (result == null) {
            result = persist(pv);
        }
        return result;
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    public List<PolicyViolation> getAllPolicyViolations() {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return query.executeList();
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final PolicyCondition policyCondition) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "policyCondition.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(policyCondition.getId());
    }

    /**
     * Returns a List of all Policy objects for a specific component.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component.id == :cid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(component.getId());
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
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (includeSuppressed) {
            query.setFilter("project.id == :pid");
        } else {
            query.setFilter("project.id == :pid && (analysis.suppressed == false || analysis.suppressed == null)");
        }
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        final PaginatedResult result = execute(query, project.getId());
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
     * Returns a List of all Policy violations for the entire portfolio.
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(boolean includeSuppressed) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (!includeSuppressed) {
            query.setFilter("analysis.suppressed == false || analysis.suppressed == null");
        }
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        final PaginatedResult result = execute(query);
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
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
        return singleResult(query.execute(component, policyViolation));
    }

    /**
     * Documents a new violation analysis. Creates a new ViolationAnalysis object if one doesn't already exists and appends
     * the specified comment along with a timestamp in the ViolationAnalysisComment trail.
     * @param component the Component
     * @param policyViolation the PolicyViolation
     * @return a ViolationAnalysis object
     */
    public ViolationAnalysis makeViolationAnalysis(Component component, PolicyViolation policyViolation,
                                                   ViolationAnalysisState violationAnalysisState, Boolean isSuppressed) {
        if (violationAnalysisState == null) {
            violationAnalysisState = ViolationAnalysisState.NOT_SET;
        }
        ViolationAnalysis violationAnalysis = getViolationAnalysis(component, policyViolation);
        if (violationAnalysis == null) {
            violationAnalysis = new ViolationAnalysis();
            violationAnalysis.setComponent(component);
            violationAnalysis.setPolicyViolation(policyViolation);
        }
        if (isSuppressed != null) {
            violationAnalysis.setSuppressed(isSuppressed);
        }
        violationAnalysis.setViolationAnalysisState(violationAnalysisState);
        violationAnalysis = persist(violationAnalysis);
        return getViolationAnalysis(violationAnalysis.getComponent(), violationAnalysis.getPolicyViolation());
    }

    /**
     * Adds a new violation analysis comment to the specified violation analysis.
     * @param violationAnalysis the violation analysis object to add a comment to
     * @param comment the comment to make
     * @param commenter the name of the principal who wrote the comment
     * @return a new ViolationAnalysisComment object
     */
    public ViolationAnalysisComment makeViolationAnalysisComment(ViolationAnalysis violationAnalysis, String comment, String commenter) {
        if (violationAnalysis == null || comment == null) {
            return null;
        }
        final ViolationAnalysisComment violationAnalysisComment = new ViolationAnalysisComment();
        violationAnalysisComment.setViolationAnalysis(violationAnalysis);
        violationAnalysisComment.setTimestamp(new Date());
        violationAnalysisComment.setComment(comment);
        violationAnalysisComment.setCommenter(commenter);
        return persist(violationAnalysisComment);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Component.
     * @param component the Component to delete violation analysis for
     */
    void deleteViolationAnalysisTrail(Component component) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Project.
     * @param project the Project to delete violation analysis for
     */
    void deleteViolationAnalysisTrail(Project project) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Policy Condition.
     * @param policyViolation policy violation to delete violation analysis for
     */
    private void deleteViolationAnalysisTrail(PolicyViolation policyViolation) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "policyViolation.id == :pid");
        query.deletePersistentAll(policyViolation.getId());
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
     * Determines if the specified LicenseGroup contains the specified License.
     * @param lg the LicenseGroup to query
     * @param license the License to query for
     * @return true if License is part of LicenseGroup, false if not
     */
    public boolean doesLicenseGroupContainLicense(final LicenseGroup lg, final License license) {
        final License l = getObjectById(License.class, license.getId());
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class, "id == :id && licenses.contains(:license)");
        return singleResult(query.execute(lg.getId(), l)) != null;
    }

    /**
     * Deletes a {@link Policy}, including all related {@link PolicyViolation}s and {@link PolicyCondition}s.
     * @param policy the {@link Policy} to delete
     */
    public void deletePolicy(final Policy policy) {
        for (final PolicyCondition condition : policy.getPolicyConditions()) {
            deletePolicyCondition(condition);
        }
        delete(policy);
    }

    /**
     * Deleted all PolicyViolation associated for the specified Component.
     * @param component the Component to delete PolicyViolation for
     */
    void deletePolicyViolations(Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all PolicyViolation associated for the specified Project.
     * @param project the Project to delete PolicyViolation for
     */
    void deletePolicyViolations(Project project) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deleted all PolicyViolation associated for the specified PolicyCondition.
     * @param policyCondition the PolicyCondition to delete PolicyViolation for
     */
    public void deletePolicyCondition(PolicyCondition policyCondition) {
        final List<PolicyViolation> violations = getAllPolicyViolations(policyCondition);
        for (PolicyViolation violation: violations) {
            deleteViolationAnalysisTrail(violation);
        }
        delete(violations);
        delete(policyCondition);
    }
}
