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
import alpine.common.validation.RegexSequence;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import alpine.model.Team;
import alpine.model.User;
import alpine.persistence.AbstractAlpineQueryManager;
import alpine.persistence.AlpineQueryManager;
import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.InvalidSortFieldException;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.metadata.MemberMetadata;
import javax.jdo.metadata.TypeMetadata;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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

    protected AlpineRequest request;

    private static final Logger LOGGER = LoggerFactory.getLogger(QueryManager.class);
    private BomQueryManager bomQueryManager;
    private ComponentQueryManager componentQueryManager;
    private AnalysisQueryManager analysisQueryManager;
    private LicenseQueryManager licenseQueryManager;
    private NotificationQueryManager notificationQueryManager;
    private PolicyQueryManager policyQueryManager;
    private ProjectQueryManager projectQueryManager;
    private RepositoryQueryManager repositoryQueryManager;
    private ServiceComponentQueryManager serviceComponentQueryManager;
    private VulnerabilityQueryManager vulnerabilityQueryManager;
    private VulnerableSoftwareQueryManager vulnerableSoftwareQueryManager;
    private TagQueryManager tagQueryManager;
    private EpssQueryManager epssQueryManager;

    /**
     * Default constructor.
     */
    public QueryManager() {
        super();
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    public QueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param request an AlpineRequest object
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
        this.request = request;
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param request an AlpineRequest object
     */
    public QueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
        this.request = request;
    }

    /**
     * @since 5.0.0
     */
    public boolean tryAcquireAdvisoryLock(long lockId) {
        if (!pm.currentTransaction().isActive()) {
            throw new IllegalStateException("Advisory locks can only be acquired within an active JDO transaction");
        }

        final Query<?> query = pm.newQuery(Query.SQL, "SELECT pg_try_advisory_xact_lock(?)");
        query.setParameters(lockId);
        return executeAndCloseResultUnique(query, Boolean.class);
    }

    /**
     * Override of {@link AbstractAlpineQueryManager#decorate(Query)} to modify the
     * method's behavior such that it always sorts by ID, in addition to whatever field
     * is requested to be sorted by via {@link #orderBy}.
     * <p>
     * This is to ensure stable ordering in case {@link #orderBy} refers to a field that
     * allows duplicates.
     *
     * @since 5.0.0
     */
    @Override
    public <T> Query<T> decorate(final Query<T> query) {
        // Clear the result to fetch if previously specified (i.e. by getting count)
        query.setResult(null);
        if (pagination != null && pagination.isPaginated()) {
            final long begin = pagination.getOffset();
            final long end = begin + pagination.getLimit();
            query.setRange(begin, end);
        }
        if (orderBy != null && RegexSequence.Pattern.STRING_IDENTIFIER.matcher(orderBy).matches() && orderDirection != OrderDirection.UNSPECIFIED) {
            // Check to see if the specified orderBy field is defined in the class being queried.
            boolean found = false;
            // NB: Only persistent fields can be used as sorting subject.
            final org.datanucleus.store.query.Query<T> iq = ((JDOQuery<T>) query).getInternalQuery();
            final String candidateField = orderBy.contains(".") ? orderBy.substring(0, orderBy.indexOf('.')) : orderBy;
            final TypeMetadata candidateTypeMetadata = pm.getPersistenceManagerFactory().getMetadata(iq.getCandidateClassName());
            if (candidateTypeMetadata == null) {
                // NB: If this happens then the entire query is broken and needs programmatic fixing.
                // Throwing an exception here to make this painfully obvious.
                throw new IllegalStateException("""
                        Persistence type metadata for candidate class %s could not be found. \
                        Querying for non-persistent types is not supported, correct your query.\
                        """.formatted(iq.getCandidateClassName()));
            }
            boolean foundPersistentMember = false;
            for (final MemberMetadata memberMetadata : candidateTypeMetadata.getMembers()) {
                if (candidateField.equals(memberMetadata.getName())) {
                    foundPersistentMember = true;
                    break;
                }
            }
            if (foundPersistentMember) {
                // NB: Changed from AbstractAlpineQueryManager#decorate to always sort by ID.
                query.setOrdering(orderBy + " " + orderDirection.name().toLowerCase() + ", id asc");
            } else {
                // Is it a non-persistent (transient) field?
                final boolean foundNonPersistentMember = Arrays.stream(iq.getCandidateClass().getDeclaredFields())
                        .anyMatch(field -> field.getName().equals(candidateField));
                if (foundNonPersistentMember) {
                    throw new InvalidSortFieldException(candidateField);
                }

                throw new InvalidSortFieldException(candidateField);
            }
        }
        return query;
    }

    /**
     * Lazy instantiation of ProjectQueryManager.
     *
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
     *
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
     *
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
     *
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
     *
     * @return a BomQueryManager object
     */
    private BomQueryManager getBomQueryManager() {
        if (bomQueryManager == null) {
            bomQueryManager = (request == null) ? new BomQueryManager(getPersistenceManager()) : new BomQueryManager(getPersistenceManager(), request);
        }
        return bomQueryManager;
    }

    /**
     * Lazy instantiation of PolicyQueryManager.
     *
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
     *
     * @return a VulnerabilityQueryManager object
     */
    private VulnerabilityQueryManager getVulnerabilityQueryManager() {
        if (vulnerabilityQueryManager == null) {
            vulnerabilityQueryManager = (request == null) ? new VulnerabilityQueryManager(getPersistenceManager()) : new VulnerabilityQueryManager(getPersistenceManager(), request);
        }
        return vulnerabilityQueryManager;
    }

    /**
     * Lazy instantiation of EpssQueryManager.
     *
     * @return a EpssQueryManager object
     */
    private EpssQueryManager getEpssQueryManager() {
        if (epssQueryManager == null) {
            epssQueryManager = (request == null) ? new EpssQueryManager(getPersistenceManager()) : new EpssQueryManager(getPersistenceManager());
        }
        return epssQueryManager;
    }

    /**
     * Lazy instantiation of VulnerableSoftwareQueryManager.
     *
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
     *
     * @return a ServiceComponentQueryManager object
     */
    private ServiceComponentQueryManager getServiceComponentQueryManager() {
        if (serviceComponentQueryManager == null) {
            serviceComponentQueryManager = (request == null) ? new ServiceComponentQueryManager(getPersistenceManager()) : new ServiceComponentQueryManager(getPersistenceManager(), request);
        }
        return serviceComponentQueryManager;
    }

    /**
     * Lazy instantiation of AnalysisQueryManager.
     *
     * @return a AnalysisQueryManager object
     */
    private AnalysisQueryManager getAnalysisQueryManager() {
        if (analysisQueryManager == null) {
            analysisQueryManager = (request == null) ? new AnalysisQueryManager(getPersistenceManager()) : new AnalysisQueryManager(getPersistenceManager(), request);
        }
        return analysisQueryManager;
    }

    /**
     * Lazy instantiation of RepositoryQueryManager.
     *
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
     *
     * @return a NotificationQueryManager object
     */
    private NotificationQueryManager getNotificationQueryManager() {
        if (notificationQueryManager == null) {
            notificationQueryManager = (request == null) ? new NotificationQueryManager(getPersistenceManager()) : new NotificationQueryManager(getPersistenceManager(), request);
        }
        return notificationQueryManager;
    }

    /**
     * Get the IDs of the {@link Team}s a given {@link Principal} is a member of.
     *
     * @return A {@link Set} of {@link Team} IDs
     */
    protected Set<Long> getTeamIds(final Principal principal) {
        List<Team> teams = switch (principal) {
            case User user when user != null -> user.getTeams();
            case ApiKey apiKey when apiKey != null -> apiKey.getTeams();
            default -> Collections.emptyList();
        };

        return Set.copyOf(teams.stream().map(Team::getId).toList());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //// BEGIN WRAPPER METHODS                                                                                      ////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public Project getProject(final String uuid) {
        return getProjectQueryManager().getProject(uuid);
    }

    public Project getProject(final String name, final String version) {
        return getProjectQueryManager().getProject(name, version);
    }

    public Project getLatestProjectVersion(final String name) {
        return getProjectQueryManager().getLatestProjectVersion(name);
    }

    public boolean hasAccess(final Principal principal, final Project project) {
        return getProjectQueryManager().hasAccess(principal, project);
    }

    void preprocessACLs(final Query<?> query, final String inputFilter, final Map<String, Object> params) {
        getProjectQueryManager().preprocessACLs(query, inputFilter, params);
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

    public Set<Tag> createTags(final Collection<String> names) {
        return getTagQueryManager().createTags(names);
    }

    public Project createProject(String name, String description, String version, Collection<Tag> tags, Project parent, PackageURL purl, Date inactiveSince, boolean commitIndex) {
        return getProjectQueryManager().createProject(name, description, version, tags, parent, purl, inactiveSince, commitIndex);
    }

    public Project createProject(final Project project, Collection<Tag> tags, boolean commitIndex) {
        return getProjectQueryManager().createProject(project, tags, commitIndex);
    }

    public Project createProject(String name, String description, String version, Collection<Tag> tags, Project parent,
                                 PackageURL purl, Date inactiveSince, boolean isLatest, boolean commitIndex) {
        return getProjectQueryManager().createProject(name, description, version, tags, parent, purl, inactiveSince, isLatest, commitIndex);
    }

    public Project updateProject(Project transientProject, boolean commitIndex) {
        return getProjectQueryManager().updateProject(transientProject, commitIndex);
    }

    public boolean updateNewProjectACL(Project transientProject, Principal principal) {
        return getProjectQueryManager().updateNewProjectACL(transientProject, principal);
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

    public Bom createBom(Project project, Date imported, Bom.Format format, String specVersion, Integer bomVersion, String serialNumber, final UUID uploadToken, Date bomGenerated) {
        return getBomQueryManager().createBom(project, imported, format, specVersion, bomVersion, serialNumber, uploadToken, bomGenerated);
    }

    public List<Bom> getAllBoms(Project project) {
        return getBomQueryManager().getAllBoms(project);
    }

    public PaginatedResult getComponentByHash(String hash) {
        return getComponentQueryManager().getComponentByHash(hash);
    }

    public PaginatedResult getComponents(
            ComponentIdentity identity,
            Project project,
            boolean includeMetrics,
            boolean excludeInactiveProjects,
            boolean onlyLatestProjectVersions) {
        return getComponentQueryManager().getComponents(
                identity,
                project,
                includeMetrics,
                excludeInactiveProjects,
                onlyLatestProjectVersions);
    }

    public Component createComponent(Component component, boolean commitIndex) {
        return getComponentQueryManager().createComponent(component, commitIndex);
    }

    public Component updateComponent(Component transientComponent, boolean commitIndex) {
        return getComponentQueryManager().updateComponent(transientComponent, commitIndex);
    }

    public Map<String, Component> getDependencyGraphForComponents(Project project, List<Component> components) {
        return getComponentQueryManager().getDependencyGraphForComponents(project, components);
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

    public License createCustomLicense(License license, boolean commitIndex) {
        return getLicenseQueryManager().createCustomLicense(license, commitIndex);
    }

    public License getCustomLicenseByName(final String licenseName) {
        return getLicenseQueryManager().getCustomLicenseByName(licenseName);
    }

    public void deleteLicense(final License license, final boolean commitIndex) {
        getLicenseQueryManager().deleteLicense(license, commitIndex);
    }

    public PaginatedResult getPolicies() {
        return getPolicyQueryManager().getPolicies();
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

    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        return getPolicyQueryManager().createPolicyCondition(policy, subject, operator, value);
    }

    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value,
                                                 final PolicyViolation.Type violationType) {
        return getPolicyQueryManager().createPolicyCondition(policy, subject, operator, value, violationType);
    }

    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        return getPolicyQueryManager().updatePolicyCondition(policyCondition);
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

    public long makeViolationAnalysis(final MakeViolationAnalysisCommand command) {
        return getPolicyQueryManager().makeViolationAnalysis(command);
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

    public Vulnerability createVulnerability(Vulnerability transientVuln) {
        return getVulnerabilityQueryManager().createVulnerability(transientVuln);
    }

    public Vulnerability updateVulnerability(Vulnerability persistentVuln, Vulnerability transientVuln) {
        return getVulnerabilityQueryManager().updateVulnerability(persistentVuln, transientVuln);
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

    public void addVulnerability(
            Vulnerability vulnerability,
            Component component,
            String analyzerIdentity) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity);
    }

    public void addVulnerability(
            Vulnerability vulnerability,
            Component component,
            String analyzerIdentity,
            String alternateIdentifier,
            String referenceUrl,
            Date attributedOn) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity, alternateIdentifier, referenceUrl, attributedOn);
    }

    public void removeVulnerability(Vulnerability vulnerability, Component component) {
        getVulnerabilityQueryManager().removeVulnerability(vulnerability, component);
    }

    public List<FindingAttribution> getFindingAttributions(Vulnerability vulnerability, Component component) {
        return getVulnerabilityQueryManager().getFindingAttributions(vulnerability, component);
    }

    public List<AffectedVersionAttribution> getAffectedVersionAttributions(Vulnerability vulnerability, VulnerableSoftware vulnerableSoftware) {
        return getVulnerabilityQueryManager().getAffectedVersionAttributions(vulnerability, vulnerableSoftware);
    }

    public List<AffectedVersionAttribution> getAffectedVersionAttributions(
            final Vulnerability vulnerability,
            final List<VulnerableSoftware> vulnerableSoftwares) {
        return getVulnerabilityQueryManager().getAffectedVersionAttributions(vulnerability, vulnerableSoftwares);
    }

    public AffectedVersionAttribution getAffectedVersionAttribution(Vulnerability vulnerability, VulnerableSoftware vulnerableSoftware, Vulnerability.Source source) {
        return getVulnerabilityQueryManager().getAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void deleteAffectedVersionAttributions(
            final Vulnerability vulnerability,
            final List<VulnerableSoftware> vulnerableSoftwares,
            final Vulnerability.Source source) {
        getVulnerabilityQueryManager().deleteAffectedVersionAttributions(vulnerability, vulnerableSoftwares, source);
    }

    public boolean hasAffectedVersionAttribution(
            final Vulnerability vulnerability,
            final VulnerableSoftware vulnerableSoftware,
            final Vulnerability.Source source) {
        return getVulnerabilityQueryManager().hasAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public boolean hasVulnerabilities(final Project project) {
        return getVulnerabilityQueryManager().hasVulnerabilities(project);
    }

    public boolean contains(Vulnerability vulnerability, Component component) {
        return getVulnerabilityQueryManager().contains(vulnerability, component);
    }

    public VulnerableSoftware getVulnerableSoftwareByCpe23(
            String cpe23,
            String versionEndExcluding,
            String versionEndIncluding,
            String versionStartExcluding,
            String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByCpe23(
                cpe23, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
    }

    public VulnerableSoftware getVulnerableSoftwareByPurl(
            final String purlType,
            final String purlNamespace,
            final String purlName,
            final String version,
            final String versionEndExcluding,
            final String versionEndIncluding,
            final String versionStartExcluding,
            final String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByPurl(
                purlType,
                purlNamespace,
                purlName,
                version,
                versionEndExcluding,
                versionEndIncluding,
                versionStartExcluding,
                versionStartIncluding);
    }

    public VulnerableSoftware getVulnerableSoftwareByPurl(
            final String purlType,
            final String purlNamespace,
            final String purlName,
            final String purlQualifiers,
            final String purlSubpath,
            final String version,
            final String versionEndExcluding,
            final String versionEndIncluding,
            final String versionStartExcluding,
            final String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByPurl(
                purlType,
                purlNamespace,
                purlName,
                purlQualifiers,
                purlSubpath,
                version,
                versionEndExcluding,
                versionEndIncluding,
                versionStartExcluding,
                versionStartIncluding);
    }

    public List<Component> matchIdentity(final Project project, final ComponentIdentity cid) {
        return getComponentQueryManager().matchIdentity(project, cid);
    }

    public boolean hasComponents(Project project) {
        return getComponentQueryManager().hasComponents(project);
    }

    public List<Component> getAllComponents(Project project) {
        return getComponentQueryManager().getAllComponents(project);
    }

    public PaginatedResult getComponents(final Project project, final boolean includeMetrics, final boolean onlyOutdated, final boolean onlyDirect) {
        return getComponentQueryManager().getComponents(project, includeMetrics, onlyOutdated, onlyDirect);
    }

    public boolean hasServiceComponents(Project project) {
        return getServiceComponentQueryManager().hasServiceComponents(project);
    }

    public List<ServiceComponent> getAllServiceComponents(Project project) {
        return getServiceComponentQueryManager().getAllServiceComponents(project);
    }

    public PaginatedResult getServiceComponents(final Project project, final boolean includeMetrics) {
        return getServiceComponentQueryManager().getServiceComponents(project, includeMetrics);
    }

    public ServiceComponent updateServiceComponent(ServiceComponent transientServiceComponent, boolean commitIndex) {
        return getServiceComponentQueryManager().updateServiceComponent(transientServiceComponent, commitIndex);
    }

    public PaginatedResult getVulnerabilities() {
        return getVulnerabilityQueryManager().getVulnerabilities();
    }

    public PaginatedResult getVulnerabilities(Component component, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilities(component, includeSuppressed);
    }

    public List<Component> getAllVulnerableComponents(Project project, Vulnerability vulnerability) {
        return getVulnerabilityQueryManager().getAllVulnerableComponents(project, vulnerability);
    }

    public List<Vulnerability> getVulnerabilities(Project project, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilities(project, includeSuppressed);
    }

    public List<VulnerabilityAlias> getVulnerabilityAliases(Vulnerability vulnerability) {
        return getVulnerabilityQueryManager().getVulnerabilityAliases(vulnerability);
    }

    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        return getAnalysisQueryManager().getAnalysis(component, vulnerability);
    }

    public long makeAnalysis(final MakeAnalysisCommand command) {
        return getAnalysisQueryManager().makeAnalysis(command);
    }

    public PaginatedResult getRepositories() {
        return getRepositoryQueryManager().getRepositories();
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

    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled, boolean internal, boolean isAuthenticationRequired, String username, String password) {
        return getRepositoryQueryManager().createRepository(type, identifier, url, enabled, internal, isAuthenticationRequired, username, password);
    }

    public Repository updateRepository(UUID uuid, String identifier, String url, boolean internal, boolean authenticationRequired, String username, String password, boolean enabled) {
        return getRepositoryQueryManager().updateRepository(uuid, identifier, url, internal, authenticationRequired, username, password, enabled);
    }

    public NotificationRule createNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        return getNotificationQueryManager().createNotificationRule(name, scope, level, publisher);
    }

    public NotificationRule createScheduledNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        return getNotificationQueryManager().createScheduledNotificationRule(name, scope, level, publisher);
    }

    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        return getNotificationQueryManager().updateNotificationRule(transientRule);
    }

    public PaginatedResult getNotificationRules(NotificationTriggerType triggerTypeFilter) {
        return getNotificationQueryManager().getNotificationRules(triggerTypeFilter);
    }

    public List<NotificationPublisher> getAllNotificationPublishers() {
        return getNotificationQueryManager().getAllNotificationPublishers();
    }

    public NotificationPublisher getNotificationPublisher(final String name) {
        return getNotificationQueryManager().getNotificationPublisher(name);
    }

    public NotificationPublisher createNotificationPublisher(
            @NonNull String name,
            String description,
            @NonNull String extensionName,
            String templateContent,
            String templateMimeType,
            boolean defaultPublisher) {
        return getNotificationQueryManager().createNotificationPublisher(
                name, description, extensionName, templateContent, templateMimeType, defaultPublisher);
    }

    /**
     * Determines if a config property is enabled or not.
     *
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

    public boolean bind(final Project project, final Collection<Tag> tags, final boolean keepExisting) {
        return getProjectQueryManager().bind(project, tags, keepExisting);
    }

    public void bind(Project project, Collection<Tag> tags) {
        getProjectQueryManager().bind(project, tags);
    }

    public boolean bind(final Policy policy, final Collection<Tag> tags, final boolean keepExisting) {
        return getPolicyQueryManager().bind(policy, tags, keepExisting);
    }

    public boolean bind(final Policy policy, final Collection<Tag> tags) {
        return getPolicyQueryManager().bind(policy, tags);
    }

    public boolean bind(final NotificationRule notificationRule, final Collection<Tag> tags, final boolean keepExisting) {
        return getNotificationQueryManager().bind(notificationRule, tags, keepExisting);
    }

    public boolean bind(final NotificationRule notificationRule, final Collection<Tag> tags) {
        return getNotificationQueryManager().bind(notificationRule, tags);
    }

    public List<Notification> getNotificationOutbox() {
        return getNotificationQueryManager().getNotificationOutbox();
    }

    public void truncateNotificationOutbox() {
        getNotificationQueryManager().truncateNotificationOutbox();
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

    public List<TagQueryManager.TaggedCollectionProjectRow> getTaggedCollectionProjects(final String tagName) {
        return getTagQueryManager().getTaggedCollectionProjects(tagName);
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

    public List<TagQueryManager.TaggedVulnerabilityRow> getTaggedVulnerabilities(final String tagName) {
        return getTagQueryManager().getTaggedVulnerabilities(tagName);
    }

    public void untagVulnerabilities(final String tagName, final Collection<String> vulnerabilityUuids) {
        getTagQueryManager().untagVulnerabilities(tagName, vulnerabilityUuids);
    }

    /**
     * Detach a persistent object using the provided fetch groups.
     * <p>
     * {@code fetchGroups} will override any other fetch groups set on the {@link PersistenceManager},
     * even the default one. If inclusion of the default fetch group is desired, it must be
     * included in {@code fetchGroups} explicitly.
     * <p>
     * Eventually, this may be moved to {@link AbstractAlpineQueryManager}.
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
     * Create the query to fetch a list of object from the datastore by theirs {@link UUID}
     *
     * @param clazz Class of the object to fetch
     * @param uuids {@link UUID} list of uuids to fetch
     * @param <T>   Type of the object
     * @return The query to execute
     * @since 4.9.0
     */
    public <T> Query<T> getObjectsByUuidsQuery(final Class<T> clazz, final List<UUID> uuids) {
        final Query<T> query = pm.newQuery(clazz, ":uuids.contains(uuid)");
        query.setParameters(uuids);
        return query;
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link Component} UUID.
     *
     * @param uuids a list of {@link Component} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getComponentDependencyGraphByUuids(final List<UUID> uuids) {
        return this.getComponentQueryManager().getDependencyGraphByUUID(uuids);
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link ServiceComponent} UUID.
     *
     * @param uuids a list of {@link ServiceComponent} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getServiceDependencyGraphByUuids(final List<UUID> uuids) {
        return this.getServiceComponentQueryManager().getDependencyGraphByUUID(uuids);
    }

    public void synchronizeVulnerableSoftware(
            final Vulnerability persistentVuln,
            final List<VulnerableSoftware> vsList,
            final Vulnerability.Source source) {
        getVulnerableSoftwareQueryManager().synchronizeVulnerableSoftware(persistentVuln, vsList, source);
    }

    public List<Component> getComponentsByPurl(String purl) {
        return getComponentQueryManager().getComponentsByPurl(purl);
    }

    public Epss getEffectiveEpssForVuln(String source, String vulnId) {
        return getEpssQueryManager().getEffectiveEpssForVuln(source, vulnId);
    }

    public Map<VulnerabilityKey, Epss> getEffectiveEpssForVulns(Collection<VulnerabilityKey> keys) {
        return getEpssQueryManager().getEffectiveEpssForVulns(keys);
    }

    public Set<Tag> resolveTags(final Collection<Tag> tags) {
        return getTagQueryManager().resolveTags(tags);
    }

    public Set<Tag> resolveTagsByName(final Collection<String> tagNames) {
        return getTagQueryManager().resolveTagsByName(tagNames);
    }

    public boolean bind(final Vulnerability vuln, final Collection<Tag> tags, final boolean keepExisting) {
        return getVulnerabilityQueryManager().bind(vuln, tags, keepExisting);
    }

    public void bind(Vulnerability vulnerability, Collection<Tag> tags) {
        getVulnerabilityQueryManager().bind(vulnerability, tags);
    }

    public PaginatedResult getVulnerabilities(final Tag tag) {
        return getVulnerabilityQueryManager().getVulnerabilities(tag);
    }

    public List<ComponentProperty> getComponentProperties(final Component component) {
        return getComponentQueryManager().getComponentProperties(component);
    }

    public List<ComponentProperty> getComponentProperties(final Component component, final String groupName, final String propertyName) {
        return getComponentQueryManager().getComponentProperties(component, groupName, propertyName);
    }

    public ComponentProperty createComponentProperty(final Component component, final String groupName, final String propertyName,
                                                     final String propertyValue, final PropertyType propertyType,
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

    public void synchronizeComponentOccurrences(final Component component, final Collection<ComponentOccurrence> occurrences) {
        getComponentQueryManager().synchronizeComponentOccurrences(component, occurrences);
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
     * @return A SQL condition that may be used to check if the {@link Principal} has access to a project
     * @since 4.12.0
     */
    public Map.Entry<String, Map<String, Object>> getProjectAclSqlCondition(final String projectTableAlias) {
        if (request == null
                || principal == null
                || !isEnabled(ACCESS_MANAGEMENT_ACL_ENABLED)
                || request.getEffectivePermissions().contains(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS))
            return Map.entry("TRUE", Collections.emptyMap());

        final Map<String, Object> params = new HashMap<>();
        final String conditionTemplate;

        switch (principal) {
            case User user -> {
                params.put("projectAclUserId", user.getId());
                conditionTemplate = /* language=SQL */ """
                        EXISTS(
                          SELECT 1
                            FROM "PROJECT_ACCESS_USERS" AS pau
                           INNER JOIN "PROJECT_HIERARCHY" AS ph
                              ON ph."PARENT_PROJECT_ID" = pau."PROJECT_ID"
                           WHERE ph."CHILD_PROJECT_ID" = "%s"."ID"
                             AND pau."USER_ID" = :projectAclUserId
                        )
                        """;
            }
            case ApiKey apiKey -> {
                params.put("projectAclApiKeyId", apiKey.getId());
                conditionTemplate = /* language=SQL */ """
                        EXISTS(
                          SELECT 1
                            FROM "APIKEYS_TEAMS" AS akt
                           INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                              ON pat."TEAM_ID" = akt."TEAM_ID"
                           INNER JOIN "PROJECT_HIERARCHY" AS ph
                              ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID"
                           WHERE akt."APIKEY_ID" = :projectAclApiKeyId
                             AND ph."CHILD_PROJECT_ID" = "%s"."ID"
                        )
                        """;
            }
            default -> {
                return Map.entry("FALSE", Collections.emptyMap());
            }
        }

        return Map.entry(conditionTemplate.formatted(projectTableAlias), params);
    }

    /**
     * @since 4.12.0
     * @return A SQL {@code OFFSET ... LIMIT ...} clause if pagination is requested, otherwise an empty string
     */
    public String getOffsetLimitSqlClause() {
        if (pagination == null || !pagination.isPaginated()) {
            return "";
        }

        return "OFFSET %d FETCH NEXT %d ROWS ONLY".formatted(pagination.getOffset(), pagination.getLimit());
    }

}
