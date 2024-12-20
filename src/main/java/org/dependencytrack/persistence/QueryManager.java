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

import alpine.common.util.BooleanUtil;
import alpine.event.framework.Event;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.notification.NotificationLevel;
import alpine.persistence.AlpineQueryManager;
import alpine.persistence.PaginatedResult;
import alpine.persistence.ScopedCustomization;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import com.github.packageurl.PackageURL;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.ClassUtils;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.VulnIdAndSource;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.resources.v1.vo.AffectedProject;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;

import jakarta.json.JsonObject;
import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.datanucleus.PropertyNames.PROPERTY_QUERY_SQL_ALLOWALL;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED;

/**
 * This QueryManager provides a concrete extension of {@link AlpineQueryManager} by
 * providing methods that operate on the Dependency-Track specific models.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@SuppressWarnings({"UnusedReturnValue", "unused"})
public class QueryManager extends AlpineQueryManager {

    private AlpineRequest request;
    private BomQueryManager bomQueryManager;
    private CacheQueryManager cacheQueryManager;
    private ComponentQueryManager componentQueryManager;
    private FindingsQueryManager findingsQueryManager;

    private FindingsSearchQueryManager findingsSearchQueryManager;
    private LicenseQueryManager licenseQueryManager;
    private MetricsQueryManager metricsQueryManager;
    private NotificationQueryManager notificationQueryManager;
    private PolicyQueryManager policyQueryManager;
    private ProjectQueryManager projectQueryManager;
    private RepositoryQueryManager repositoryQueryManager;
    private ServiceComponentQueryManager serviceComponentQueryManager;
    private VexQueryManager vexQueryManager;
    private VulnerabilityQueryManager vulnerabilityQueryManager;
    private VulnerableSoftwareQueryManager vulnerableSoftwareQueryManager;

    private TagQueryManager tagQueryManager;

    /**
     * Default constructor.
     */
    public QueryManager() {
        super();
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    public QueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param request an AlpineRequest object
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
        this.request = request;
    }

    /**
     * Constructs a new QueryManager.
     * @param request an AlpineRequest object
     */
    public QueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
        this.request = request;
    }

    /**
     * Lazy instantiation of ProjectQueryManager.
     * @return a ProjectQueryManager object
     */
    private ProjectQueryManager getProjectQueryManager() {
        if (projectQueryManager == null) {
            projectQueryManager = (request == null) ? new ProjectQueryManager(getPersistenceManager()) : new ProjectQueryManager(getPersistenceManager(), request);
        }
        return projectQueryManager;
    }

    /**
     * Lazy instantiation of TagQueryManager.
     * @return a TagQueryManager object
     */
    private TagQueryManager getTagQueryManager() {
        if (tagQueryManager == null) {
            tagQueryManager = (request == null) ? new TagQueryManager(getPersistenceManager()) : new TagQueryManager(getPersistenceManager(), request);
        }
        return tagQueryManager;
    }

    /**
     * Lazy instantiation of ComponentQueryManager.
     * @return a ComponentQueryManager object
     */
    private ComponentQueryManager getComponentQueryManager() {
        if (componentQueryManager == null) {
            componentQueryManager = (request == null) ? new ComponentQueryManager(getPersistenceManager()) : new ComponentQueryManager(getPersistenceManager(), request);
        }
        return componentQueryManager;
    }

    /**
     * Lazy instantiation of LicenseQueryManager.
     * @return a LicenseQueryManager object
     */
    private LicenseQueryManager getLicenseQueryManager() {
        if (licenseQueryManager == null) {
            licenseQueryManager = (request == null) ? new LicenseQueryManager(getPersistenceManager()) : new LicenseQueryManager(getPersistenceManager(), request);
        }
        return licenseQueryManager;
    }

    /**
     * Lazy instantiation of BomQueryManager.
     * @return a BomQueryManager object
     */
    private BomQueryManager getBomQueryManager() {
        if (bomQueryManager == null) {
            bomQueryManager = (request == null) ? new BomQueryManager(getPersistenceManager()) : new BomQueryManager(getPersistenceManager(), request);
        }
        return bomQueryManager;
    }

    /**
     * Lazy instantiation of VexQueryManager.
     * @return a VexQueryManager object
     */
    private VexQueryManager getVexQueryManager() {
        if (vexQueryManager == null) {
            vexQueryManager = (request == null) ? new VexQueryManager(getPersistenceManager()) : new VexQueryManager(getPersistenceManager(), request);
        }
        return vexQueryManager;
    }

    /**
     * Lazy instantiation of PolicyQueryManager.
     * @return a PolicyQueryManager object
     */
    private PolicyQueryManager getPolicyQueryManager() {
        if (policyQueryManager == null) {
            policyQueryManager = (request == null) ? new PolicyQueryManager(getPersistenceManager()) : new PolicyQueryManager(getPersistenceManager(), request);
        }
        return policyQueryManager;
    }

    /**
     * Lazy instantiation of VulnerabilityQueryManager.
     * @return a VulnerabilityQueryManager object
     */
    private VulnerabilityQueryManager getVulnerabilityQueryManager() {
        if (vulnerabilityQueryManager == null) {
            vulnerabilityQueryManager = (request == null) ? new VulnerabilityQueryManager(getPersistenceManager()) : new VulnerabilityQueryManager(getPersistenceManager(), request);
        }
        return vulnerabilityQueryManager;
    }

    /**
     * Lazy instantiation of VulnerableSoftwareQueryManager.
     * @return a VulnerableSoftwareQueryManager object
     */
    private VulnerableSoftwareQueryManager getVulnerableSoftwareQueryManager() {
        if (vulnerableSoftwareQueryManager == null) {
            vulnerableSoftwareQueryManager = (request == null) ? new VulnerableSoftwareQueryManager(getPersistenceManager()) : new VulnerableSoftwareQueryManager(getPersistenceManager(), request);
        }
        return vulnerableSoftwareQueryManager;
    }

    /**
     * Lazy instantiation of ServiceComponentQueryManager.
     * @return a ServiceComponentQueryManager object
     */
    private ServiceComponentQueryManager getServiceComponentQueryManager() {
        if (serviceComponentQueryManager == null) {
            serviceComponentQueryManager = (request == null) ? new ServiceComponentQueryManager(getPersistenceManager()) : new ServiceComponentQueryManager(getPersistenceManager(), request);
        }
        return serviceComponentQueryManager;
    }

    /**
     * Lazy instantiation of FindingsQueryManager.
     * @return a FindingsQueryManager object
     */
    private FindingsQueryManager getFindingsQueryManager() {
        if (findingsQueryManager == null) {
            findingsQueryManager = (request == null) ? new FindingsQueryManager(getPersistenceManager()) : new FindingsQueryManager(getPersistenceManager(), request);
        }
        return findingsQueryManager;
    }

    /**
     * Lazy instantiation of FindingsSearchQueryManager.
     * @return a FindingsSearchQueryManager object
     */
    private FindingsSearchQueryManager getFindingsSearchQueryManager() {
        if (findingsSearchQueryManager == null) {
            findingsSearchQueryManager = (request == null) ? new FindingsSearchQueryManager(getPersistenceManager()) : new FindingsSearchQueryManager(getPersistenceManager(), request);
        }
        return findingsSearchQueryManager;
    }

    /**
     * Lazy instantiation of MetricsQueryManager.
     * @return a MetricsQueryManager object
     */
    private MetricsQueryManager getMetricsQueryManager() {
        if (metricsQueryManager == null) {
            metricsQueryManager = (request == null) ? new MetricsQueryManager(getPersistenceManager()) : new MetricsQueryManager(getPersistenceManager(), request);
        }
        return metricsQueryManager;
    }

    /**
     * Lazy instantiation of RepositoryQueryManager.
     * @return a RepositoryQueryManager object
     */
    private RepositoryQueryManager getRepositoryQueryManager() {
        if (repositoryQueryManager == null) {
            repositoryQueryManager = (request == null) ? new RepositoryQueryManager(getPersistenceManager()) : new RepositoryQueryManager(getPersistenceManager(), request);
        }
        return repositoryQueryManager;
    }

    /**
     * Lazy instantiation of NotificationQueryManager.
     * @return a NotificationQueryManager object
     */
    private NotificationQueryManager getNotificationQueryManager() {
        if (notificationQueryManager == null) {
            notificationQueryManager = (request == null) ? new NotificationQueryManager(getPersistenceManager()) : new NotificationQueryManager(getPersistenceManager(), request);
        }
        return notificationQueryManager;
    }

    /**
     * Lazy instantiation of CacheQueryManager.
     * @return a CacheQueryManager object
     */
    private CacheQueryManager getCacheQueryManager() {
        if (cacheQueryManager == null) {
            cacheQueryManager = (request == null) ? new CacheQueryManager(getPersistenceManager()) : new CacheQueryManager(getPersistenceManager(), request);
        }
        return cacheQueryManager;
    }

    /**
     * Get the IDs of the {@link Team}s a given {@link Principal} is a member of.
     *
     * @return A {@link Set} of {@link Team} IDs
     * @since 4.11.1
     */
    protected Set<Long> getTeamIds(final Principal principal) {
        final var principalTeamIds = new HashSet<Long>();

        if (principal instanceof final UserPrincipal userPrincipal
                && userPrincipal.getTeams() != null) {
            for (final Team userInTeam : userPrincipal.getTeams()) {
                principalTeamIds.add(userInTeam.getId());
            }
        } else if (principal instanceof final ApiKey apiKey
                && apiKey.getTeams() != null) {
            for (final Team userInTeam : apiKey.getTeams()) {
                principalTeamIds.add(userInTeam.getId());
            }
        }

        return principalTeamIds;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //// BEGIN WRAPPER METHODS                                                                                      ////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public PaginatedResult getProjects(final boolean includeMetrics, final boolean excludeInactive, final boolean onlyRoot, final Team notAssignedToTeam) {
        return getProjectQueryManager().getProjects(includeMetrics, excludeInactive, onlyRoot, notAssignedToTeam);
    }

    public PaginatedResult getProjects(final boolean includeMetrics) {
        return getProjectQueryManager().getProjects(includeMetrics);
    }

    public PaginatedResult getProjects() {
        return getProjectQueryManager().getProjects();
    }

    public List<Project> getAllProjects() {
        return getProjectQueryManager().getAllProjects();
    }

    public List<Project> getAllProjects(boolean excludeInactive) {
        return getProjectQueryManager().getAllProjects(excludeInactive);
    }

    public PaginatedResult getProjects(final String name, final boolean excludeInactive, final boolean onlyRoot, final Team notAssignedToTeam) {
        return getProjectQueryManager().getProjects(name, excludeInactive, onlyRoot, notAssignedToTeam);
    }

    public Project getProject(final String uuid) {
        return getProjectQueryManager().getProject(uuid);
    }

    public Project getProject(final String name, final String version) {
        return getProjectQueryManager().getProject(name, version);
    }

    public Project getLatestProjectVersion(final String name) {
        return getProjectQueryManager().getLatestProjectVersion(name);
    }

    public PaginatedResult getProjects(final Team team, final boolean excludeInactive, final boolean bypass, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(team, excludeInactive, bypass, onlyRoot);
    }

    public PaginatedResult getProjectsWithoutDescendantsOf(final boolean excludeInactive, final Project project) {
        return getProjectQueryManager().getProjectsWithoutDescendantsOf(excludeInactive, project);
    }

    public PaginatedResult getProjectsWithoutDescendantsOf(final String name, final boolean excludeInactive, final Project project) {
        return getProjectQueryManager().getProjectsWithoutDescendantsOf(name, excludeInactive, project);
    }

    public boolean hasAccess(final Principal principal, final Project project) {
        return getProjectQueryManager().hasAccess(principal, project);
    }

    void preprocessACLs(final Query<?> query, final String inputFilter, final Map<String, Object> params, final boolean bypass) {
        getProjectQueryManager().preprocessACLs(query, inputFilter, params, bypass);
    }

    public PaginatedResult getProjects(final Tag tag, final boolean includeMetrics, final boolean excludeInactive, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(tag, includeMetrics, excludeInactive, onlyRoot);
    }

    public PaginatedResult getProjects(final Classifier classifier, final boolean includeMetrics, final boolean excludeInactive, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(classifier, includeMetrics, excludeInactive, onlyRoot);
    }

    public PaginatedResult getChildrenProjects(final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        return getProjectQueryManager().getChildrenProjects(uuid, includeMetrics, excludeInactive);
    }

    public PaginatedResult getChildrenProjects(final Tag tag, final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        return getProjectQueryManager().getChildrenProjects(tag, uuid, includeMetrics, excludeInactive);
    }

    public PaginatedResult getChildrenProjects(final Classifier classifier, final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        return getProjectQueryManager().getChildrenProjects(classifier, uuid, includeMetrics, excludeInactive);
    }

    public PaginatedResult getProjects(final Tag tag) {
        return getProjectQueryManager().getProjects(tag);
    }

    public boolean doesProjectExist(final String name, final String version) {
        return getProjectQueryManager().doesProjectExist(name, version);
    }

    public Tag getTagByName(final String name) {
        return getTagQueryManager().getTagByName(name);
    }

    public Tag createTag(final String name) {
        return getTagQueryManager().createTag(name);
    }

    public List<Tag> createTags(final List<String> names) {
        return getTagQueryManager().createTags(names);
    }

    public List<Tag> resolveTags(final List<Tag> tags) {
        return getTagQueryManager().resolveTags(tags);
    }

    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent, PackageURL purl, boolean active, boolean commitIndex) {
        return getProjectQueryManager().createProject(name, description, version, tags, parent, purl, active, commitIndex);
    }
    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent,
                                 PackageURL purl, boolean active, boolean isLatest, boolean commitIndex) {
        return getProjectQueryManager().createProject(name, description, version, tags, parent, purl, active, isLatest, commitIndex);
    }

    public Project createProject(final Project project, List<Tag> tags, boolean commitIndex) {
        return getProjectQueryManager().createProject(project, tags, commitIndex);
    }

    public Project updateProject(Project transientProject, boolean commitIndex) {
        return getProjectQueryManager().updateProject(transientProject, commitIndex);
    }

    public boolean updateNewProjectACL(Project transientProject, Principal principal) {
        return getProjectQueryManager().updateNewProjectACL(transientProject, principal);
    }

    public Project clone(UUID from, String newVersion, boolean includeTags, boolean includeProperties,
                         boolean includeComponents, boolean includeServices, boolean includeAuditHistory,
                         boolean includeACL, boolean includePolicyViolations, boolean makeCloneLatest) {
        return getProjectQueryManager().clone(from, newVersion, includeTags, includeProperties,
                includeComponents, includeServices, includeAuditHistory, includeACL, includePolicyViolations, makeCloneLatest);
    }

    public Project updateLastBomImport(Project p, Date date, String bomFormat) {
        return getProjectQueryManager().updateLastBomImport(p, date, bomFormat);
    }

    public void recursivelyDelete(final Project project, final boolean commitIndex) {
        getProjectQueryManager().recursivelyDelete(project, commitIndex);
    }

    public void deleteProjectsByUUIDs(Collection<UUID> uuids) {
        getProjectQueryManager().deleteProjectsByUUIDs(uuids);
    }

    public ProjectProperty createProjectProperty(final Project project, final String groupName, final String propertyName,
                                                 final String propertyValue, final ProjectProperty.PropertyType propertyType,
                                                 final String description) {
        return getProjectQueryManager().createProjectProperty(project, groupName, propertyName, propertyValue, propertyType, description);
    }

    public ProjectProperty getProjectProperty(final Project project, final String groupName, final String propertyName) {
        return getProjectQueryManager().getProjectProperty(project, groupName, propertyName);
    }

    public List<ProjectProperty> getProjectProperties(final Project project) {
        return getProjectQueryManager().getProjectProperties(project);
    }

    public Bom createBom(Project project, Date imported, Bom.Format format, String specVersion, Integer bomVersion, String serialNumber) {
        return getBomQueryManager().createBom(project, imported, format, specVersion, bomVersion, serialNumber);
    }

    public List<Bom> getAllBoms(Project project) {
        return getBomQueryManager().getAllBoms(project);
    }

    public void deleteBoms(Project project) {
        getBomQueryManager().deleteBoms(project);
    }

    public Vex createVex(Project project, Date imported, Vex.Format format, String specVersion, Integer vexVersion, String serialNumber) {
        return getVexQueryManager().createVex(project, imported, format, specVersion, vexVersion, serialNumber);
    }

    public List<Vex> getAllVexs(Project project) {
        return getVexQueryManager().getAllVexs(project);
    }

    public void deleteVexs(Project project) {
        getVexQueryManager().deleteVexs(project);
    }

    public PaginatedResult getComponents(final boolean includeMetrics) {
        return getComponentQueryManager().getComponents(includeMetrics);
    }

    public PaginatedResult getComponents() {
        return getComponentQueryManager().getComponents(false);
    }

    public List<Component> getAllComponents() {
        return getComponentQueryManager().getAllComponents();
    }

    public PaginatedResult getComponentByHash(String hash) {
        return getComponentQueryManager().getComponentByHash(hash);
    }

    public PaginatedResult getComponents(ComponentIdentity identity) {
        return getComponentQueryManager().getComponents(identity);
    }

    public PaginatedResult getComponents(ComponentIdentity identity, boolean includeMetrics) {
        return getComponentQueryManager().getComponents(identity, includeMetrics);
    }

    public PaginatedResult getComponents(ComponentIdentity identity, Project project, boolean includeMetrics) {
        return getComponentQueryManager().getComponents(identity, project, includeMetrics);
    }

    public Component createComponent(Component component, boolean commitIndex) {
        return getComponentQueryManager().createComponent(component, commitIndex);
    }

    public Component cloneComponent(Component sourceComponent, Project destinationProject, boolean commitIndex) {
        return getComponentQueryManager().cloneComponent(sourceComponent, destinationProject, commitIndex);
    }

    public Component updateComponent(Component transientComponent, boolean commitIndex) {
        return getComponentQueryManager().updateComponent(transientComponent, commitIndex);
    }

    void deleteComponents(Project project) {
        getComponentQueryManager().deleteComponents(project);
    }

    public void recursivelyDelete(Component component, boolean commitIndex) {
        getComponentQueryManager().recursivelyDelete(component, commitIndex);
    }

    public Map<String, Component> getDependencyGraphForComponents(Project project, List<Component> components) {
        return getComponentQueryManager().getDependencyGraphForComponents(project, components);
    }

    public List<ComponentProperty> getComponentProperties(final Component component) {
        return getComponentQueryManager().getComponentProperties(component);
    }

    public List<ComponentProperty> getComponentProperties(final Component component, final String groupName, final String propertyName) {
        return getComponentQueryManager().getComponentProperties(component, groupName, propertyName);
    }

    public ComponentProperty createComponentProperty(final Component component, final String groupName, final String propertyName,
                                                     final String propertyValue, final IConfigProperty.PropertyType propertyType,
                                                     final String description) {
        return getComponentQueryManager()
                .createComponentProperty(component, groupName, propertyName, propertyValue, propertyType, description);
    }

    public long deleteComponentPropertyByUuid(final Component component, final UUID uuid) {
        return getComponentQueryManager().deleteComponentPropertyByUuid(component, uuid);
    }

    public void synchronizeComponentProperties(final Component component, final List<ComponentProperty> properties) {
        getComponentQueryManager().synchronizeComponentProperties(component, properties);
    }

    public PaginatedResult getLicenses() {
        return getLicenseQueryManager().getLicenses();
    }

    public List<License> getAllLicensesConcise() {
        return getLicenseQueryManager().getAllLicensesConcise();
    }

    public License getLicense(String licenseId) {
        return getLicenseQueryManager().getLicense(licenseId);
    }

    public License getLicenseByIdOrName(final String licenseIdOrName) {
        return getLicenseQueryManager().getLicenseByIdOrName(licenseIdOrName);
    }

    public License getCustomLicense(String licenseName) {
        return getLicenseQueryManager().getCustomLicense(licenseName);
    }

    public License getCustomLicenseByName(final String licenseName) {
        return getLicenseQueryManager().getCustomLicenseByName(licenseName);
    }

    public License synchronizeLicense(License license, boolean commitIndex) {
        return getLicenseQueryManager().synchronizeLicense(license, commitIndex);
    }


    public License createCustomLicense(License license, boolean commitIndex) {
        return getLicenseQueryManager().createCustomLicense(license, commitIndex);
    }

    public void deleteLicense(final License license, final boolean commitIndex) {
        getLicenseQueryManager().deleteLicense(license, commitIndex);
    }

    public PaginatedResult getPolicies() {
        return getPolicyQueryManager().getPolicies();
    }

    public List<Policy> getAllPolicies() {
        return getPolicyQueryManager().getAllPolicies();
    }

    public Policy getPolicy(final String name) {
        return getPolicyQueryManager().getPolicy(name);
    }

    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState) {
        return this.createPolicy(name, operator, violationState, false);
    }
    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState, boolean onlyLatestProjectVersion) {
        return getPolicyQueryManager().createPolicy(name, operator, violationState, onlyLatestProjectVersion);
    }

    public void removeProjectFromPolicies(final Project project) {
        getPolicyQueryManager().removeProjectFromPolicies(project);
    }

    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        return getPolicyQueryManager().createPolicyCondition(policy, subject, operator, value);
    }

    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        return getPolicyQueryManager().updatePolicyCondition(policyCondition);
    }

    public synchronized void reconcilePolicyViolations(final Component component, final List<PolicyViolation> policyViolations) {
        getPolicyQueryManager().reconcilePolicyViolations(component, policyViolations);
    }

    public synchronized PolicyViolation addPolicyViolationIfNotExist(final PolicyViolation pv) {
        return getPolicyQueryManager().addPolicyViolationIfNotExist(pv);
    }

    public PolicyViolation clonePolicyViolation(PolicyViolation sourcePolicyViolation, Component destinationComponent) {
        return getPolicyQueryManager().clonePolicyViolation(sourcePolicyViolation, destinationComponent);
    }

    public List<PolicyViolation> getAllPolicyViolations() {
        return getPolicyQueryManager().getAllPolicyViolations();
    }

    public List<PolicyViolation> getAllPolicyViolations(final PolicyCondition policyCondition) {
        return getPolicyQueryManager().getAllPolicyViolations(policyCondition);
    }

    public List<PolicyViolation> getAllPolicyViolations(final Component component) {
        return getPolicyQueryManager().getAllPolicyViolations(component);
    }

    public List<PolicyViolation> getAllPolicyViolations(final Component component, final boolean includeSuppressed) {
        return getPolicyQueryManager().getAllPolicyViolations(component, includeSuppressed);
    }

    public List<PolicyViolation> getAllPolicyViolations(final Project project) {
        return getPolicyQueryManager().getAllPolicyViolations(project);
    }

    public PaginatedResult getPolicyViolations(final Project project, boolean includeSuppressed) {
        return getPolicyQueryManager().getPolicyViolations(project, includeSuppressed);
    }

    public PaginatedResult getPolicyViolations(final Component component, boolean includeSuppressed) {
        return getPolicyQueryManager().getPolicyViolations(component, includeSuppressed);
    }

    public PaginatedResult getPolicyViolations(boolean includeSuppressed, boolean showInactive, Map<String, String> filters) {
        return getPolicyQueryManager().getPolicyViolations(includeSuppressed, showInactive, filters);
    }

    public ViolationAnalysis getViolationAnalysis(Component component, PolicyViolation policyViolation) {
        return getPolicyQueryManager().getViolationAnalysis(component, policyViolation);
    }

    public ViolationAnalysis makeViolationAnalysis(Component component, PolicyViolation policyViolation,
                                                   ViolationAnalysisState violationAnalysisState, Boolean isSuppressed) {
        return getPolicyQueryManager().makeViolationAnalysis(component, policyViolation, violationAnalysisState, isSuppressed);
    }

    public ViolationAnalysisComment makeViolationAnalysisComment(ViolationAnalysis violationAnalysis, String comment, String commenter) {
        return getPolicyQueryManager().makeViolationAnalysisComment(violationAnalysis, comment, commenter);
    }

    void deleteViolationAnalysisTrail(Component component) {
        getPolicyQueryManager().deleteViolationAnalysisTrail(component);
    }

    void deleteViolationAnalysisTrail(Project project) {
        getPolicyQueryManager().deleteViolationAnalysisTrail(project);
    }

    public PaginatedResult getLicenseGroups() {
        return getPolicyQueryManager().getLicenseGroups();
    }

    public LicenseGroup getLicenseGroup(final String name) {
        return getPolicyQueryManager().getLicenseGroup(name);
    }

    public LicenseGroup createLicenseGroup(String name) {
        return getPolicyQueryManager().createLicenseGroup(name);
    }

    public boolean doesLicenseGroupContainLicense(final LicenseGroup lg, final License license) {
        return getPolicyQueryManager().doesLicenseGroupContainLicense(lg, license);
    }

    public void deletePolicy(final Policy policy) {
        getPolicyQueryManager().deletePolicy(policy);
    }

    void deletePolicyViolations(Component component) {
        getPolicyQueryManager().deletePolicyViolations(component);
    }

    void deletePolicyViolations(Project project) {
        getPolicyQueryManager().deletePolicyViolations(project);
    }

    public long getAuditedCount(final Component component, final PolicyViolation.Type type) {
        return getPolicyQueryManager().getAuditedCount(component, type);
    }

    public void deletePolicyCondition(PolicyCondition policyCondition) {
        getPolicyQueryManager().deletePolicyCondition(policyCondition);
    }

    public Vulnerability createVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        return getVulnerabilityQueryManager().createVulnerability(vulnerability, commitIndex);
    }

    public Vulnerability updateVulnerability(Vulnerability transientVulnerability, boolean commitIndex) {
        return getVulnerabilityQueryManager().updateVulnerability(transientVulnerability, commitIndex);
    }

    public Vulnerability synchronizeVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        return getVulnerabilityQueryManager().synchronizeVulnerability(vulnerability, commitIndex);
    }

    public Vulnerability getVulnerabilityByVulnId(String source, String vulnId) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, false);
    }

    public Vulnerability getVulnerabilityByVulnId(String source, String vulnId, boolean includeVulnerableSoftware) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, includeVulnerableSoftware);
    }

    public Vulnerability getVulnerabilityByVulnId(Vulnerability.Source source, String vulnId) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, false);
    }

    public Vulnerability getVulnerabilityByVulnId(Vulnerability.Source source, String vulnId, boolean includeVulnerableSoftware) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, includeVulnerableSoftware);
    }

    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity);
    }

    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity,
                                 String alternateIdentifier, String referenceUrl) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity, alternateIdentifier, referenceUrl);
    }

    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity,
                                 String alternateIdentifier, String referenceUrl, Date attributedOn) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity, alternateIdentifier, referenceUrl, attributedOn);
    }

    public void removeVulnerability(Vulnerability vulnerability, Component component) {
        getVulnerabilityQueryManager().removeVulnerability(vulnerability, component);
    }

    public FindingAttribution getFindingAttribution(Vulnerability vulnerability, Component component) {
        return getVulnerabilityQueryManager().getFindingAttribution(vulnerability, component);
    }

    void deleteFindingAttributions(Component component) {
        getVulnerabilityQueryManager().deleteFindingAttributions(component);
    }

    void deleteFindingAttributions(Project project) {
        getVulnerabilityQueryManager().deleteFindingAttributions(project);
    }

    public List<VulnerableSoftware> reconcileVulnerableSoftware(final Vulnerability vulnerability,
                                                                final List<VulnerableSoftware> vsListOld,
                                                                final List<VulnerableSoftware> vsList,
                                                                final Vulnerability.Source source) {
        return getVulnerabilityQueryManager().reconcileVulnerableSoftware(vulnerability, vsListOld, vsList, source);
    }

    public List<AffectedVersionAttribution> getAffectedVersionAttributions(Vulnerability vulnerability, VulnerableSoftware vulnerableSoftware) {
        return getVulnerabilityQueryManager().getAffectedVersionAttributions(vulnerability, vulnerableSoftware);
    }

    public List<AffectedVersionAttribution> getAffectedVersionAttributions(final Vulnerability vulnerability,
                                                                           final List<VulnerableSoftware> vulnerableSoftwares) {
        return getVulnerabilityQueryManager().getAffectedVersionAttributions(vulnerability, vulnerableSoftwares);
    }

    public AffectedVersionAttribution getAffectedVersionAttribution(Vulnerability vulnerability, VulnerableSoftware vulnerableSoftware, Vulnerability.Source source) {
        return getVulnerabilityQueryManager().getAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void updateAffectedVersionAttributions(final Vulnerability vulnerability,
                                                  final List<VulnerableSoftware> vsList,
                                                  final Vulnerability.Source source) {
        getVulnerabilityQueryManager().updateAffectedVersionAttributions(vulnerability, vsList, source);
    }

    public void updateAffectedVersionAttribution(final Vulnerability vulnerability,
                                                 final VulnerableSoftware vulnerableSoftware,
                                                 final Vulnerability.Source source) {
        getVulnerabilityQueryManager().updateAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void deleteAffectedVersionAttributions(final Vulnerability vulnerability,
                                                  final List<VulnerableSoftware> vulnerableSoftwares,
                                                  final Vulnerability.Source source) {
        getVulnerabilityQueryManager().deleteAffectedVersionAttributions(vulnerability, vulnerableSoftwares, source);
    }

    public void deleteAffectedVersionAttribution(final Vulnerability vulnerability,
                                                 final VulnerableSoftware vulnerableSoftware,
                                                 final Vulnerability.Source source) {
        getVulnerabilityQueryManager().deleteAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void deleteAffectedVersionAttributions(final Vulnerability vulnerability) {
        getVulnerabilityQueryManager().deleteAffectedVersionAttributions(vulnerability);
    }

    public boolean hasAffectedVersionAttribution(final Vulnerability vulnerability,
                                                 final VulnerableSoftware vulnerableSoftware,
                                                 final Vulnerability.Source source) {
        return getVulnerabilityQueryManager().hasAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void synchronizeVulnerableSoftware(
            final Vulnerability persistentVuln,
            final List<VulnerableSoftware> vsList,
            final Vulnerability.Source source) {
        getVulnerableSoftwareQueryManager().synchronizeVulnerableSoftware(persistentVuln, vsList, source);
    }

    public boolean contains(Vulnerability vulnerability, Component component) {
        return getVulnerabilityQueryManager().contains(vulnerability, component);
    }

    public VulnerableSoftware getVulnerableSoftwareByCpe23(String cpe23,
                                                           String versionEndExcluding, String versionEndIncluding,
                                                           String versionStartExcluding, String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByCpe23(cpe23, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
    }

    public PaginatedResult getVulnerableSoftware() {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftware();
    }

    public List<VulnerableSoftware> getAllVulnerableSoftwareByCpe(final String cpeString) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftwareByCpe(cpeString);
    }

    public VulnerableSoftware getVulnerableSoftwareByPurl(String purlType, String purlNamespace, String purlName,
                                                          String versionEndExcluding, String versionEndIncluding,
                                                          String versionStartExcluding, String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByPurl(purlType, purlNamespace, purlName, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
    }

    public VulnerableSoftware getVulnerableSoftwareByPurl(
            final String purl,
            final String versionEndExcluding,
            final String versionEndIncluding,
            final String versionStartExcluding,
            final String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByPurl(
                purl,
                versionEndExcluding,
                versionEndIncluding,
                versionStartExcluding,
                versionStartIncluding);
    }

    public List<VulnerableSoftware> getVulnerableSoftwareByVulnId(final String source, final String vulnId) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByVulnId(source, vulnId);
    }

    public List<VulnerableSoftware> getAllVulnerableSoftwareByPurl(final PackageURL purl) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftwareByPurl(purl);
    }

    public List<VulnerableSoftware> getAllVulnerableSoftware(final String cpePart, final String cpeVendor, final String cpeProduct, final PackageURL purl) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftware(cpePart, cpeVendor, cpeProduct, purl);
    }

    public Component matchSingleIdentityExact(final Project project, final ComponentIdentity cid) {
        return getComponentQueryManager().matchSingleIdentityExact(project, cid);
    }

    public Component matchFirstIdentityExact(final Project project, final ComponentIdentity cid) {
        return getComponentQueryManager().matchFirstIdentityExact(project, cid);
    }

    public List<Component> matchIdentity(final Project project, final ComponentIdentity cid) {
        return getComponentQueryManager().matchIdentity(project, cid);
    }

    public List<Component> matchIdentity(final ComponentIdentity cid) {
        return getComponentQueryManager().matchIdentity(cid);
    }

    public void reconcileComponents(Project project, List<Component> existingProjectComponents, List<Component> components) {
        getComponentQueryManager().reconcileComponents(project, existingProjectComponents, components);
    }

    public List<Component> getAllComponents(Project project) {
        return getComponentQueryManager().getAllComponents(project);
    }

    public PaginatedResult getComponents(final Project project, final boolean includeMetrics) {
        return getComponentQueryManager().getComponents(project, includeMetrics);
    }

    public PaginatedResult getComponents(final Project project, final boolean includeMetrics, final boolean onlyOutdated, final boolean onlyDirect) {
        return getComponentQueryManager().getComponents(project, includeMetrics, onlyOutdated, onlyDirect);
    }

    public boolean hasComponents(final Project project) {
        return getComponentQueryManager().hasComponents(project);
    }

    public ServiceComponent matchServiceIdentity(final Project project, final ComponentIdentity cid) {
        return getServiceComponentQueryManager().matchServiceIdentity(project, cid);
    }

    public void reconcileServiceComponents(Project project, List<ServiceComponent> existingProjectServices, List<ServiceComponent> services) {
        getServiceComponentQueryManager().reconcileServiceComponents(project, existingProjectServices, services);
    }

    public ServiceComponent createServiceComponent(ServiceComponent service, boolean commitIndex) {
        return getServiceComponentQueryManager().createServiceComponent(service, commitIndex);
    }

    public List<ServiceComponent> getAllServiceComponents() {
        return getServiceComponentQueryManager().getAllServiceComponents();
    }

    public List<ServiceComponent> getAllServiceComponents(Project project) {
        return getServiceComponentQueryManager().getAllServiceComponents(project);
    }

    public PaginatedResult getServiceComponents() {
        return getServiceComponentQueryManager().getServiceComponents();
    }

    public PaginatedResult getServiceComponents(final boolean includeMetrics) {
        return getServiceComponentQueryManager().getServiceComponents(includeMetrics);
    }

    public PaginatedResult getServiceComponents(final Project project, final boolean includeMetrics) {
        return getServiceComponentQueryManager().getServiceComponents(project, includeMetrics);
    }

    public ServiceComponent cloneServiceComponent(ServiceComponent sourceService, Project destinationProject, boolean commitIndex) {
        return getServiceComponentQueryManager().cloneServiceComponent(sourceService, destinationProject, commitIndex);
    }

    public ServiceComponent updateServiceComponent(ServiceComponent transientServiceComponent, boolean commitIndex) {
        return getServiceComponentQueryManager().updateServiceComponent(transientServiceComponent, commitIndex);
    }

    public boolean hasServiceComponents(final Project project) {
        return getServiceComponentQueryManager().hasServiceComponents(project);
    }

    public void recursivelyDelete(ServiceComponent service, boolean commitIndex) {
        getServiceComponentQueryManager().recursivelyDelete(service, commitIndex);
    }

    public PaginatedResult getVulnerabilities() {
        return getVulnerabilityQueryManager().getVulnerabilities();
    }

    public PaginatedResult getVulnerabilities(Component component) {
        return getVulnerabilityQueryManager().getVulnerabilities(component);
    }

    public PaginatedResult getVulnerabilities(Component component, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilities(component, includeSuppressed);
    }

    public List<Component> getAllVulnerableComponents(Project project, Vulnerability vulnerability, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getAllVulnerableComponents(project, vulnerability, includeSuppressed);
    }

    public List<Vulnerability> getAllVulnerabilities(Component component) {
        return getVulnerabilityQueryManager().getAllVulnerabilities(component);
    }

    public List<Vulnerability> getAllVulnerabilities(Component component, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getAllVulnerabilities(component, includeSuppressed);
    }

    public long getVulnerabilityCount(Project project, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilityCount(project, includeSuppressed);
    }

    public List<Vulnerability> getVulnerabilities(Project project, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilities(project, includeSuppressed);
    }

    public long getAuditedCount() {
        return getFindingsQueryManager().getAuditedCount();
    }

    public long getAuditedCount(Project project) {
        return getFindingsQueryManager().getAuditedCount(project);
    }

    public long getAuditedCount(Component component) {
        return getFindingsQueryManager().getAuditedCount(component);
    }

    public long getAuditedCount(Project project, Component component) {
        return getFindingsQueryManager().getAuditedCount(project, component);
    }

    public long getSuppressedCount() {
        return getFindingsQueryManager().getSuppressedCount();
    }

    public long getSuppressedCount(Project project) {
        return getFindingsQueryManager().getSuppressedCount(project);
    }

    public long getSuppressedCount(Component component) {
        return getFindingsQueryManager().getSuppressedCount(component);
    }

    public long getSuppressedCount(Project project, Component component) {
        return getFindingsQueryManager().getSuppressedCount(project, component);
    }

    public List<AffectedProject> getAffectedProjects(Vulnerability vulnerability) {
        return getVulnerabilityQueryManager().getAffectedProjects(vulnerability);
    }

    public VulnerabilityAlias synchronizeVulnerabilityAlias(VulnerabilityAlias alias) {
        return getVulnerabilityQueryManager().synchronizeVulnerabilityAlias(alias);
    }

    public List<VulnerabilityAlias> getVulnerabilityAliases(Vulnerability vulnerability) {
        return getVulnerabilityQueryManager().getVulnerabilityAliases(vulnerability);
    }

    public Map<VulnIdAndSource, List<VulnerabilityAlias>> getVulnerabilityAliases(final Collection<VulnIdAndSource> vulnIdAndSources) {
        return getVulnerabilityQueryManager().getVulnerabilityAliases(vulnIdAndSources);
    }

    List<Analysis> getAnalyses(Project project) {
        return getFindingsQueryManager().getAnalyses(project);
    }

    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        return getFindingsQueryManager().getAnalysis(component, vulnerability);
    }

    public Analysis makeAnalysis(Component component, Vulnerability vulnerability, AnalysisState analysisState,
                                 AnalysisJustification analysisJustification, AnalysisResponse analysisResponse,
                                 String analysisDetails, Boolean isSuppressed) {
        return getFindingsQueryManager().makeAnalysis(component, vulnerability, analysisState, analysisJustification, analysisResponse, analysisDetails, isSuppressed);
    }

    public AnalysisComment makeAnalysisComment(Analysis analysis, String comment, String commenter) {
        return getFindingsQueryManager().makeAnalysisComment(analysis, comment, commenter);
    }

    void deleteAnalysisTrail(Component component) {
        getFindingsQueryManager().deleteAnalysisTrail(component);
    }

    void deleteAnalysisTrail(Project project) {
        getFindingsQueryManager().deleteAnalysisTrail(project);
    }

    public List<Finding> getFindings(Project project) {
        return getFindingsQueryManager().getFindings(project);
    }

    public List<Finding> getFindings(Project project, boolean includeSuppressed) {
        return getFindingsQueryManager().getFindings(project, includeSuppressed);
    }

    public PaginatedResult getAllFindings(final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        return getFindingsSearchQueryManager().getAllFindings(filters, showSuppressed, showInactive);
    }

    public PaginatedResult getAllFindingsGroupedByVulnerability(final Map<String, String> filters, final boolean showInactive) {
        return getFindingsSearchQueryManager().getAllFindingsGroupedByVulnerability(filters, showInactive);
    }

    public List<VulnerabilityMetrics> getVulnerabilityMetrics() {
        return getMetricsQueryManager().getVulnerabilityMetrics();
    }

    public PortfolioMetrics getMostRecentPortfolioMetrics() {
        return getMetricsQueryManager().getMostRecentPortfolioMetrics();
    }

    public PaginatedResult getPortfolioMetrics() {
        return getMetricsQueryManager().getPortfolioMetrics();
    }

    public List<PortfolioMetrics> getPortfolioMetricsSince(Date since) {
        return getMetricsQueryManager().getPortfolioMetricsSince(since);
    }

    public ProjectMetrics getMostRecentProjectMetrics(Project project) {
        return getMetricsQueryManager().getMostRecentProjectMetrics(project);
    }

    public PaginatedResult getProjectMetrics(Project project) {
        return getMetricsQueryManager().getProjectMetrics(project);
    }

    public List<ProjectMetrics> getProjectMetricsSince(Project project, Date since) {
        return getMetricsQueryManager().getProjectMetricsSince(project, since);
    }

    public DependencyMetrics getMostRecentDependencyMetrics(Component component) {
        return getMetricsQueryManager().getMostRecentDependencyMetrics(component);
    }

    public PaginatedResult getDependencyMetrics(Component component) {
        return getMetricsQueryManager().getDependencyMetrics(component);
    }

    public List<DependencyMetrics> getDependencyMetricsSince(Component component, Date since) {
        return getMetricsQueryManager().getDependencyMetricsSince(component, since);
    }

    public void synchronizeVulnerabilityMetrics(List<VulnerabilityMetrics> metrics) {
        getMetricsQueryManager().synchronizeVulnerabilityMetrics(metrics);
    }

    void deleteMetrics(Project project) {
        getMetricsQueryManager().deleteMetrics(project);
    }

    void deleteMetrics(Component component) {
        getMetricsQueryManager().deleteMetrics(component);
    }

    public PaginatedResult getRepositories() {
        return getRepositoryQueryManager().getRepositories();
    }

    public List<Repository> getAllRepositories() {
        return getRepositoryQueryManager().getAllRepositories();
    }

    public PaginatedResult getRepositories(RepositoryType type) {
        return getRepositoryQueryManager().getRepositories(type);
    }

    public List<Repository> getAllRepositoriesOrdered(RepositoryType type) {
        return getRepositoryQueryManager().getAllRepositoriesOrdered(type);
    }

    public boolean repositoryExist(RepositoryType type, String identifier) {
        return getRepositoryQueryManager().repositoryExist(type, identifier);
    }

    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled, boolean internal, boolean isAuthenticationRequired, String username, String password, String bearerToken) {
        return getRepositoryQueryManager().createRepository(type, identifier, url, enabled, internal, isAuthenticationRequired, username, password, bearerToken);
    }

    public Repository updateRepository(UUID uuid, String identifier, String url, boolean internal, boolean authenticationRequired, String username, String password, String bearerToken, boolean enabled) {
        return getRepositoryQueryManager().updateRepository(uuid, identifier, url, internal, authenticationRequired, username, password, bearerToken, enabled);
    }

    public RepositoryMetaComponent getRepositoryMetaComponent(RepositoryType repositoryType, String namespace, String name) {
        return getRepositoryQueryManager().getRepositoryMetaComponent(repositoryType, namespace, name);
    }

    public synchronized RepositoryMetaComponent synchronizeRepositoryMetaComponent(final RepositoryMetaComponent transientRepositoryMetaComponent) {
        return getRepositoryQueryManager().synchronizeRepositoryMetaComponent(transientRepositoryMetaComponent);
    }

    public NotificationRule createNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        return getNotificationQueryManager().createNotificationRule(name, scope, level, publisher);
    }

    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        return getNotificationQueryManager().updateNotificationRule(transientRule);
    }

    public PaginatedResult getNotificationRules() {
        return getNotificationQueryManager().getNotificationRules();
    }

    public List<NotificationPublisher> getAllNotificationPublishers() {
        return getNotificationQueryManager().getAllNotificationPublishers();
    }

    public NotificationPublisher getNotificationPublisher(final String name) {
        return getNotificationQueryManager().getNotificationPublisher(name);
    }

    public NotificationPublisher getDefaultNotificationPublisher(final Class<? extends Publisher> clazz) {
        return getNotificationQueryManager().getDefaultNotificationPublisher(clazz);
    }

    public NotificationPublisher createNotificationPublisher(final String name, final String description,
                                                             final Class<? extends Publisher> publisherClass, final String templateContent,
                                                             final String templateMimeType, final boolean defaultPublisher) {
        return getNotificationQueryManager().createNotificationPublisher(name, description, publisherClass, templateContent, templateMimeType, defaultPublisher);
    }

    public NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
        return getNotificationQueryManager().updateNotificationPublisher(transientPublisher);
    }

    public void deleteNotificationPublisher(NotificationPublisher notificationPublisher) {
        getNotificationQueryManager().deleteNotificationPublisher(notificationPublisher);
    }

    public void removeProjectFromNotificationRules(final Project project) {
        getNotificationQueryManager().removeProjectFromNotificationRules(project);
    }

    public void removeTeamFromNotificationRules(final Team team) {
        getNotificationQueryManager().removeTeamFromNotificationRules(team);
    }

    /**
     * Determines if a config property is enabled or not.
     * @param configPropertyConstants the property to query
     * @return true if enabled, false if not
     */
    public boolean isEnabled(final ConfigPropertyConstants configPropertyConstants) {
        final ConfigProperty property = getConfigProperty(
                configPropertyConstants.getGroupName(), configPropertyConstants.getPropertyName()
        );
        if (property != null && ConfigProperty.PropertyType.BOOLEAN == property.getPropertyType()) {
            return BooleanUtil.valueOf(property.getPropertyValue());
        }
        return false;
    }

    public ComponentAnalysisCache getComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetHost, String targetType, String target) {
        return getCacheQueryManager().getComponentAnalysisCache(cacheType, targetHost, targetType, target);
    }

    public List<ComponentAnalysisCache> getComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetType, String target) {
        return getCacheQueryManager().getComponentAnalysisCache(cacheType, targetType, target);
    }

    public synchronized void updateComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetHost, String targetType, String target, Date lastOccurrence, JsonObject result) {
        getCacheQueryManager().updateComponentAnalysisCache(cacheType, targetHost, targetType, target, lastOccurrence, result);
    }

    public void clearComponentAnalysisCache() {
        getCacheQueryManager().clearComponentAnalysisCache();
    }

    public void clearComponentAnalysisCache(Date threshold) {
        getCacheQueryManager().clearComponentAnalysisCache(threshold);
    }

    public boolean bind(final NotificationRule notificationRule, final Collection<Tag> tags) {
        return getNotificationQueryManager().bind(notificationRule, tags);
    }

    public void bind(Project project, List<Tag> tags) {
        getProjectQueryManager().bind(project, tags);
    }

    public boolean bind(final Policy policy, final Collection<Tag> tags) {
        return getPolicyQueryManager().bind(policy, tags);
    }

    /**
     * Commits the Lucene index.
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @param clazz       the indexable class to commit the index of
     */
    public void commitSearchIndex(boolean commitIndex, Class clazz) {
        if (commitIndex) {
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, clazz));
        }
    }

    /**
     * Commits the Lucene index.
     * @param clazz the indexable class to commit the index of
     */
    public void commitSearchIndex(Class clazz) {
        commitSearchIndex(true, clazz);
    }

    public boolean hasAccessManagementPermission(final Object principal) {
        if (principal instanceof final UserPrincipal userPrincipal) {
            return hasAccessManagementPermission(userPrincipal);
        } else if (principal instanceof final ApiKey apiKey) {
            return hasAccessManagementPermission(apiKey);
        }

        throw new IllegalArgumentException("Provided principal is of invalid type " + ClassUtils.getName(principal));
    }

    public boolean hasAccessManagementPermission(final UserPrincipal userPrincipal) {
        return getProjectQueryManager().hasAccessManagementPermission(userPrincipal);
    }

    public boolean hasAccessManagementPermission(final ApiKey apiKey) {
        return getProjectQueryManager().hasAccessManagementPermission(apiKey);
    }

    public List<TagQueryManager.TagListRow> getTags() {
        return getTagQueryManager().getTags();
    }

    public void deleteTags(final Collection<String> tagNames) {
        getTagQueryManager().deleteTags(tagNames);
    }

    public List<TagQueryManager.TaggedProjectRow> getTaggedProjects(final String tagName) {
        return getTagQueryManager().getTaggedProjects(tagName);
    }

    public void tagProjects(final String tagName, final Collection<String> projectUuids) {
        getTagQueryManager().tagProjects(tagName, projectUuids);
    }

    public void untagProjects(final String tagName, final Collection<String> projectUuids) {
        getTagQueryManager().untagProjects(tagName, projectUuids);
    }

    public List<TagQueryManager.TaggedPolicyRow> getTaggedPolicies(final String tagName) {
        return getTagQueryManager().getTaggedPolicies(tagName);
    }

    public void tagPolicies(final String tagName, final Collection<String> policyUuids) {
        getTagQueryManager().tagPolicies(tagName, policyUuids);
    }

    public void untagPolicies(final String tagName, final Collection<String> policyUuids) {
        getTagQueryManager().untagPolicies(tagName, policyUuids);
    }

    public PaginatedResult getTagsForPolicy(String policyUuid) {
        return getTagQueryManager().getTagsForPolicy(policyUuid);
    }

    public List<TagQueryManager.TaggedNotificationRuleRow> getTaggedNotificationRules(final String tagName) {
        return getTagQueryManager().getTaggedNotificationRules(tagName);
    }

    public void tagNotificationRules(final String tagName, final Collection<String> notificationRuleUuids) {
        getTagQueryManager().tagNotificationRules(tagName, notificationRuleUuids);
    }

    public void untagNotificationRules(final String tagName, final Collection<String> notificationRuleUuids) {
        getTagQueryManager().untagNotificationRules(tagName, notificationRuleUuids);
    }

    /**
     * Fetch an object from the datastore by its {@link UUID}, using the provided fetch groups.
     * <p>
     * {@code fetchGroups} will override any other fetch groups set on the {@link PersistenceManager},
     * even the default one. If inclusion of the default fetch group is desired, it must be
     * included in {@code fetchGroups} explicitly.
     * <p>
     * Eventually, this may be moved to {@link alpine.persistence.AbstractAlpineQueryManager}.
     *
     * @param clazz       Class of the object to fetch
     * @param uuid        {@link UUID} of the object to fetch
     * @param fetchGroups Fetch groups to use for this operation
     * @return The object if found, otherwise {@code null}
     * @param <T>         Type of the object
     * @throws Exception When closing the query failed
     * @since 4.6.0
     */
    public <T> T getObjectByUuid(final Class<T> clazz, final UUID uuid, final List<String> fetchGroups) throws Exception {
        try (final Query<T> query = pm.newQuery(clazz)) {
            query.setFilter("uuid == :uuid");
            query.setParameters(uuid);
            query.getFetchPlan().setGroups(fetchGroups);
            return query.executeUnique();
        }
    }

    /**
     * Detach a persistent object using the provided fetch groups.
     * <p>
     * {@code fetchGroups} will override any other fetch groups set on the {@link PersistenceManager},
     * even the default one. If inclusion of the default fetch group is desired, it must be
     * included in {@code fetchGroups} explicitly.
     * <p>
     * Eventually, this may be moved to {@link alpine.persistence.AbstractAlpineQueryManager}.
     *
     * @param object      The persistent object to detach
     * @param fetchGroups Fetch groups to use for this operation
     * @param <T>         Type of the object
     * @return The detached object
     * @since 4.8.0
     */
    public <T> T detachWithGroups(final T object, final List<String> fetchGroups) {
        final int origDetachOptions = pm.getFetchPlan().getDetachmentOptions();
        final Set<?> origFetchGroups = pm.getFetchPlan().getGroups();
        try {
            pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
            pm.getFetchPlan().setGroups(fetchGroups);
            return pm.detachCopy(object);
        } finally {
            // Restore previous settings to not impact other operations performed
            // by this persistence manager.
            pm.getFetchPlan().setDetachmentOptions(origDetachOptions);
            pm.getFetchPlan().setGroups(origFetchGroups);
        }
    }

    /**
     * Fetch a list of object from the datastore by theirs {@link UUID}
     *
     * @param clazz Class of the object to fetch
     * @param uuids {@link UUID} list of uuids to fetch
     * @return The list of objects found
     * @param <T>   Type of the object
     * @since 4.9.0
     */
    public <T> List<T> getObjectsByUuids(final Class<T> clazz, final List<UUID> uuids) {
        final Query<T> query = getObjectsByUuidsQuery(clazz, uuids);
        return query.executeList();
    }

    /**
     * Create the query to fetch a list of object from the datastore by theirs {@link UUID}
     *
     * @param clazz Class of the object to fetch
     * @param uuids {@link UUID} list of uuids to fetch
     * @return The query to execute
     * @param <T>   Type of the object
     * @since 4.9.0
     */
    public <T> Query<T> getObjectsByUuidsQuery(final Class<T> clazz, final List<UUID> uuids) {
        final Query<T> query = pm.newQuery(clazz, ":uuids.contains(uuid)");
        query.setParameters(uuids);
        return query;
    }

    public void recursivelyDeleteTeam(Team team) {
        runInTransaction(() -> {
            pm.deletePersistentAll(team.getApiKeys());

            try (var ignored = new ScopedCustomization(pm).withProperty(PROPERTY_QUERY_SQL_ALLOWALL, "true")) {
                final Query<?> aclDeleteQuery = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, """
                        DELETE FROM "PROJECT_ACCESS_TEAMS" WHERE "PROJECT_ACCESS_TEAMS"."TEAM_ID" = ?""");
                executeAndCloseWithArray(aclDeleteQuery, team.getId());
            }

            pm.deletePersistent(team);
        });
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link Component} UUID.
     * @param uuids a list of {@link Component} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getComponentDependencyGraphByUuids(final List<UUID> uuids) {
        return this.getComponentQueryManager().getDependencyGraphByUUID(uuids);
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link ServiceComponent} UUID.
     * @param uuids a list of {@link ServiceComponent} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getServiceDependencyGraphByUuids(final List<UUID> uuids) {
        return this.getServiceComponentQueryManager().getDependencyGraphByUUID(uuids);
    }

    /**
     * Returns a list of all {@link RepositoryMetaComponent} objects by {@link RepositoryQueryManager.RepositoryMetaComponentSearch} with batchSize 10.
     * @param list a list of {@link RepositoryQueryManager.RepositoryMetaComponentSearch}
     * @return a list of {@link RepositoryMetaComponent} objects
     * @since 4.9.0
     */
    public List<RepositoryMetaComponent> getRepositoryMetaComponentsBatch(final List<RepositoryQueryManager.RepositoryMetaComponentSearch> list) {
        return getRepositoryMetaComponentsBatch(list, 10);
    }

    /**
     * Returns a list of all {@link RepositoryMetaComponent} objects by {@link RepositoryQueryManager.RepositoryMetaComponentSearch} UUID.
     * @param list      a list of {@link RepositoryQueryManager.RepositoryMetaComponentSearch}
     * @param batchSize the batch size
     * @return a list of {@link RepositoryMetaComponent} objects
     * @since 4.9.0
     */
    public List<RepositoryMetaComponent> getRepositoryMetaComponentsBatch(final List<RepositoryQueryManager.RepositoryMetaComponentSearch> list, final int batchSize) {
        final List<RepositoryMetaComponent> results = new ArrayList<>(list.size());

        // Split the list into batches
        for (List<RepositoryQueryManager.RepositoryMetaComponentSearch> batch : Lists.partition(list, batchSize)) {
            results.addAll(this.getRepositoryQueryManager().getRepositoryMetaComponents(batch));
        }

        return results;
    }

    public List<RepositoryMetaComponent> getRepositoryMetaComponents(final List<RepositoryQueryManager.RepositoryMetaComponentSearch> list) {
        return getRepositoryQueryManager().getRepositoryMetaComponents(list);
    }

    /**
     * @see #getProjectAclSqlCondition(String)
     * @since 4.12.0
     */
    public Map.Entry<String, Map<String, Object>> getProjectAclSqlCondition() {
        return getProjectAclSqlCondition("PROJECT");
    }

    /**
     * @param projectTableAlias Name or alias of the {@code PROJECT} table to use in the condition.
     * @return A SQL condition that may be used to check if the {@link #principal} has access to a project
     * @since 4.12.0
     */
    public Map.Entry<String, Map<String, Object>> getProjectAclSqlCondition(final String projectTableAlias) {
        if (request == null) {
            return Map.entry(/* true */ "1=1", Collections.emptyMap());
        }

        if (principal == null || !isEnabled(ACCESS_MANAGEMENT_ACL_ENABLED) || hasAccessManagementPermission(principal)) {
            return Map.entry(/* true */ "1=1", Collections.emptyMap());
        }

        final var teamIds = new ArrayList<>(getTeamIds(principal));
        if (teamIds.isEmpty()) {
            return Map.entry(/* false */ "1=2", Collections.emptyMap());
        }


        // NB: Need to work around the fact that the RDBMSes can't agree on how to do member checks. Oh joy! :)))
        final var params = new HashMap<String, Object>();
        final var teamIdChecks = new ArrayList<String>();
        for (int i = 0; i < teamIds.size(); i++) {
            teamIdChecks.add("\"PROJECT_ACCESS_TEAMS\".\"TEAM_ID\" = :teamId" + i);
            params.put("teamId" + i, teamIds.get(i));
        }

        return Map.entry("""
                EXISTS (
                  SELECT 1
                    FROM "PROJECT_ACCESS_TEAMS"
                   WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "%s"."ID"
                     AND (%s)
                )""".formatted(projectTableAlias, String.join(" OR ", teamIdChecks)), params);
    }

    /**
     * @since 4.12.0
     * @return A SQL {@code OFFSET ... LIMIT ...} clause if pagination is requested, otherwise an empty string
     */
    public String getOffsetLimitSqlClause() {
        if (pagination == null || !pagination.isPaginated()) {
            return "";
        }

        final String clauseTemplate;
        if (DbUtil.isMssql()) {
            clauseTemplate = "OFFSET %d ROWS FETCH NEXT %d ROWS ONLY";
        } else if (DbUtil.isMysql()) {
            // NB: Order of limit and offset is different for MySQL...
            return "LIMIT %s OFFSET %s".formatted(pagination.getLimit(), pagination.getOffset());
        } else {
            clauseTemplate = "OFFSET %d FETCH NEXT %d ROWS ONLY";
        }

        return clauseTemplate.formatted(pagination.getOffset(), pagination.getLimit());
    }

}