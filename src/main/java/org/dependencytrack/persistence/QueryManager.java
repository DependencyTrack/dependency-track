/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.persistence;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.model.ConfigProperty;
import alpine.notification.NotificationLevel;
import alpine.persistence.AlpineQueryManager;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.lang3.StringUtils;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetrics;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Dependency;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Evidence;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.License;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Scan;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.util.NotificationUtil;
import javax.jdo.FetchPlan;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * This QueryManager provides a concrete extension of {@link AlpineQueryManager} by
 * providing methods that operate on the Dependency-Track specific models.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class QueryManager extends AlpineQueryManager {

    private static final boolean ENFORCE_AUTHORIZATION = Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHORIZATION);

    /**
     * Default constructor.
     */
    public QueryManager() {
        super();
    }

    /**
     * Constructs a new QueryManager.
     * @param request an AlpineRequest object
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
    }

    /**
     * Returns a list of all projects.
     * @return a List of Projects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getProjects() {
        final Query query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a list of all projects.
     * This method if designed NOT to provide paginated results.
     * @return a List of Projects
     */
    @SuppressWarnings("unchecked")
    public List<Project> getAllProjects() {
        final Query query = pm.newQuery(Project.class);
        query.setOrdering("name asc");
        return query.executeResultList(Project.class);
    }

    /**
     * Returns a list of projects by it's name.
     * @param name the name of the Projects (required)
     * @return a List of Project objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getProjects(String name) {
        final Query query = pm.newQuery(Project.class, "name == :name");
        if (orderBy == null) {
            query.setOrdering("version desc");
        }
        return execute(query, name);
    }

    /**
     * Returns a project by it's name and version.
     * @param name the name of the Project (required)
     * @param version the version of the Project (or null)
     * @return a Project object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Project getProject(String name, String version) {
        final Query query = pm.newQuery(Project.class, "name == :name && version == :version");
        final List<Project> result = (List<Project>) query.execute(name, version);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns a paginated result of projects by tag.
     * @param tag the tag associated with the Project
     * @return a List of Projects that contain the tag
     */
    public PaginatedResult getProjects(Tag tag) {
        final Query query = pm.newQuery(Project.class, "tags.contains(:tag)");
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        return execute(query, tag);
    }

    /**
     * Returns a list of Tag objects what have been resolved. It resolved
     * tags by querying the database to retrieve the tag. If the tag does
     * not exist, the tag will be created and returned with other resolved
     * tags.
     * @param tags a List of Tags to resolve
     * @return List of resolved Tags
     */
    @SuppressWarnings("unchecked")
    public synchronized List<Tag> resolveTags(List<Tag> tags) {
        if (tags == null) {
            return new ArrayList<>();
        }
        final List<Tag> resolvedTags = new ArrayList<>();
        final List<String> unresolvedTags = new ArrayList<>();
        for (Tag tag: tags) {
            final String trimmedTag = StringUtils.trimToNull(tag.getName());
            if (trimmedTag != null) {
                final Tag resolvedTag = getTagByName(trimmedTag);
                if (resolvedTag != null) {
                    resolvedTags.add(resolvedTag);
                } else {
                    unresolvedTags.add(trimmedTag);
                }
            }
        }
        resolvedTags.addAll(createTags(unresolvedTags));
        return resolvedTags;
    }

    /**
     * Returns a list of Tag objects by name.
     * @param name the name of the Tag
     * @return a Tag object
     */
    @SuppressWarnings("unchecked")
    public Tag getTagByName(String name) {
        final String trimmedTag = StringUtils.trimToNull(name);
        final Query query = pm.newQuery(Tag.class, "name == :name");
        final List<Tag> result = (List<Tag>) query.execute(trimmedTag);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Creates a new Tag object with the specified name.
     * @param name the name of the Tag to create
     * @return the created Tag object
     */
    public Tag createTag(String name) {
        final String trimmedTag = StringUtils.trimToNull(name);
        final Tag resolvedTag = getTagByName(trimmedTag);
        if (resolvedTag != null) {
            return resolvedTag;
        }
        final Tag tag = new Tag();
        tag.setName(trimmedTag);
        return persist(tag);
    }

    /**
     * Creates one or more Tag objects from the specified name(s).
     * @param names the name(s) of the Tag(s) to create
     * @return the created Tag object(s)
     */
    public List<Tag> createTags(List<String> names) {
        final List<Tag> newTags = new ArrayList<>();
        for (String name: names) {
            final String trimmedTag = StringUtils.trimToNull(name);
            if (getTagByName(trimmedTag) == null) {
                final Tag tag = new Tag();
                tag.setName(trimmedTag);
                newTags.add(tag);
            }
        }
        return new ArrayList<>(persist(newTags));
    }

    /**
     * Creates a new Project.
     * @param name the name of the project to create
     * @param description a description of the project
     * @param version the project version
     * @param tags a List of Tags - these will be resolved if necessary
     * @param parent an optional parent Project
     * @param purl an optional Package URL
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the created Project
     */
    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent, String purl, boolean commitIndex) {
        final Project project = new Project();
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        if (parent != null) {
            project.setParent(parent);
        }
        project.setPurl(purl);
        final Project result = persist(project);

        List<Tag> resolvedTags = resolveTags(tags);
        bind(project, resolvedTags);

        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);
        return result;
    }

    /**
     * Updates an existing Project.
     * @param uuid the uuid of the project to update
     * @param name the name of the project
     * @param description a description of the project
     * @param version the project version
     * @param tags a List of Tags - these will be resolved if necessary
     * @param purl an optional Package URL
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the updated Project
     */
    public Project updateProject(UUID uuid, String name, String description, String version, List<Tag> tags, String purl, boolean commitIndex) {
        final Project project = getObjectByUuid(Project.class, uuid);
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setPurl(purl);

        List<Tag> resolvedTags = resolveTags(tags);
        bind(project, resolvedTags);

        final Project result = persist(project);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);
        return result;
    }

    /**
     * Updates the last time a scan was imported.
     * @param date the date of the last scan import
     * @return the updated Project
     */
    public Project updateLastScanImport(Project p, Date date) {
        final Project project = getObjectById(Project.class, p.getId());
        project.setLastScanImport(date);
        return persist(project);
    }

    /**
     * Updates the last time a bom was imported.
     * @param date the date of the last bom import
     * @return the updated Project
     */
    public Project updateLastBomImport(Project p, Date date) {
        final Project project = getObjectById(Project.class, p.getId());
        project.setLastBomImport(date);
        return persist(project);
    }

    /**
     * Deletes a Project and all objects dependant on the project.
     * @param project the Project to delete
     */
    public void recursivelyDelete(Project project) {
        if (project.getChildren() != null) {
            for (Project child: project.getChildren()) {
                recursivelyDelete(child);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Project result = pm.getObjectById(Project.class, project.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));

        deleteAnalysisTrail(project);
        deleteMetrics(project);
        deleteDependencies(project);
        deleteScans(project);
        deleteBoms(project);
        delete(project.getProperties());
        delete(getScans(project));
        delete(getBoms(project));
        delete(project.getChildren());
        delete(project);
    }

    /**
     * Creates a key/value pair (ProjectProperty) for the specified Project.
     * @param project the Project to create the property for
     * @param groupName the group name of the property
     * @param propertyName the name of the property
     * @param propertyValue the value of the property
     * @param propertyType the type of property
     * @param description a description of the property
     * @return the created ProjectProperty object
     */
    public ProjectProperty createProjectProperty(final Project project, final String groupName, final String propertyName,
                                                 final String propertyValue, final ConfigProperty.PropertyType propertyType,
                                                 final String description) {
        final ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName(groupName);
        property.setPropertyName(propertyName);
        property.setPropertyValue(propertyValue);
        property.setPropertyType(propertyType);
        property.setDescription(description);
        return persist(property);
    }

    /**
     * Creates a new Scan.
     * @param project the Project to create a Scan for
     * @param executed the Date when the scan was executed
     * @param imported the Date when the scan was imported
     * @return a new Scan object
     */
    public Scan createScan(Project project, Date executed, Date imported) {
        final Scan scan = new Scan();
        scan.setExecuted(executed);
        scan.setImported(imported);
        scan.setProject(project);
        return persist(scan);
    }

    /**
     * Returns a list of all Scans for the specified Project.
     * @param project the Project to retrieve scans for
     * @return a List of Scans
     */
    @SuppressWarnings("unchecked")
    public List<Scan> getScans(Project project) {
        final Query query = pm.newQuery(Scan.class, "project == :project");
        return (List<Scan>) query.execute(project);
    }

    /**
     * Deletes scans belonging to the specified Project.
     * @param project the Project to delete scans for
     */
    public void deleteScans(Project project) {
        final Query query = pm.newQuery(Scan.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deletes scans belonging to the specified Component.
     * @param component the Component to delete scans for
     */
    @SuppressWarnings("unchecked")
    public void deleteScans(Component component) {
        final Query query = pm.newQuery(Scan.class, "components.contains(component)");
        for (Scan scan: (List<Scan>) query.execute(component)) {
            scan.getComponents().remove(component);
            persist(scan);
        }
    }

    /**
     * Creates a new Bom.
     * @param project the Project to create a Bom for
     * @param imported the Date when the bom was imported
     * @return a new Bom object
     */
    public Bom createBom(Project project, Date imported) {
        final Bom bom = new Bom();
        bom.setImported(imported);
        bom.setProject(project);
        return persist(bom);
    }

    /**
     * Returns a list of all Bom for the specified Project.
     * @param project the Project to retrieve boms for
     * @return a List of Boms
     */
    @SuppressWarnings("unchecked")
    public List<Bom> getBoms(Project project) {
        final Query query = pm.newQuery(Bom.class, "project == :project");
        return (List<Bom>) query.execute(project);
    }

    /**
     * Deletes boms belonging to the specified Project.
     * @param project the Project to delete boms for
     */
    public void deleteBoms(Project project) {
        final Query query = pm.newQuery(Bom.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deletes boms belonging to the specified Component.
     * @param component the Component to delete boms for
     */
    @SuppressWarnings("unchecked")
    public void deleteBoms(Component component) {
        final Query query = pm.newQuery(Bom.class, "components.contains(component)");
        for (Bom bom: (List<Bom>) query.execute(component)) {
            bom.getComponents().remove(component);
            persist(bom);
        }
    }

    /**
     * Returns a list of all Components defined in the datastore.
     * @return a List of Components
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getComponents() {
        final Query query = pm.newQuery(Component.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a Component by its hash. Supports MD5, SHA-1, SHA-256, SHA-512, SHA3-256, and SHA3-512 hashes.
     * @param hash the hash of the component to retrieve
     * @return a Component, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Component getComponentByHash(String hash) {
        if (hash == null) {
            return null;
        }
        final Query query;
        if (hash.length() == 32) {
            query = pm.newQuery(Component.class, "md5 == :hash");
        } else if (hash.length() == 40) {
            query = pm.newQuery(Component.class, "sha1 == :hash");
        } else if (hash.length() == 64) {
            query = pm.newQuery(Component.class, "sha256 == :hash || sha3_256 == :hash");
        } else if (hash.length() == 128) {
            query = pm.newQuery(Component.class, "sha512 == :hash || sha3_512 == :hash");
        } else {
            return null;
        }
        final List<Component> result = (List<Component>) query.execute(hash);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns a Component by group, name, and version.
     * @param group the group of the component to retrieve
     * @param name the name of the component to retrieve
     * @param version the version of the component to retrieve
     * @return a Component, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Component getComponentByAttributes(String group, String name, String version) {
        final Query query = pm.newQuery(Component.class, "group == :group && name == :name && version == :version");
        final List<Component> result = (List<Component>) query.execute(group, name, version);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Creates a new Component.
     * @param component the Component to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new Component
     */
    public Component createComponent(Component component, boolean commitIndex) {
        final Component result = persist(component);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Component.class);
        return result;
    }

    /**
     * Updated an existing Component.
     * @param transientComponent the component to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Component
     */
    public Component updateComponent(Component transientComponent, boolean commitIndex) {
        final Component component = getObjectByUuid(Component.class, transientComponent.getUuid());
        component.setName(transientComponent.getName());
        component.setVersion(transientComponent.getVersion());
        component.setGroup(transientComponent.getGroup());
        component.setFilename(transientComponent.getFilename());
        component.setMd5(transientComponent.getMd5());
        component.setSha1(transientComponent.getSha1());
        component.setSha256(transientComponent.getSha256());
        component.setSha512(transientComponent.getSha512());
        component.setSha3_256(transientComponent.getSha3_256());
        component.setSha3_512(transientComponent.getSha3_512());
        component.setDescription(transientComponent.getDescription());
        component.setCopyright(transientComponent.getCopyright());
        component.setLicense(transientComponent.getLicense());
        component.setResolvedLicense(transientComponent.getResolvedLicense());
        component.setParent(transientComponent.getParent());
        component.setCpe(transientComponent.getCpe());
        component.setPurl(transientComponent.getPurl());
        final Component result = persist(component);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Component.class);
        return result;
    }

    /**
     * Deletes a Component and all objects dependant on the component.
     * @param component the Component to delete
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     */
    public void recursivelyDelete(Component component, boolean commitIndex) {
        if (component.getChildren() != null) {
            for (Component child: component.getChildren()) {
                recursivelyDelete(child, false);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Component result = pm.getObjectById(Component.class, component.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));

        deleteAnalysisTrail(component);
        deleteMetrics(component);
        deleteDependencies(component);
        deleteScans(component);
        deleteBoms(component);
        delete(component);
        commitSearchIndex(commitIndex, Component.class);
    }

    /**
     * Creates new evidence for a Component.
     * @param component the Component to create evidence for
     * @param type the type of evidence
     * @param confidenceScore the confidence score
     * @param source the source of where the evidence was obtained from
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @return a new Evidence object
     */
    public Evidence createEvidence(Component component, String type, int confidenceScore,
                                    String source, String name, String value) {
        final Evidence evidence = new Evidence();
        evidence.setComponent(component);
        evidence.setType(type);
        evidence.setConfidence(confidenceScore);
        evidence.setSource(source);
        evidence.setName(name);
        evidence.setValue(value);
        return persist(evidence);
    }

    /**
     * Returns a List of all License objects.
     * @return a List of all License objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getLicenses() {
        final Query query = pm.newQuery(License.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter) || licenseId.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a License object from the specified SPDX license ID.
     * @param licenseId the SPDX license ID to retrieve
     * @return a License object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public License getLicense(String licenseId) {
        final Query query = pm.newQuery(License.class, "licenseId == :licenseId");
        final List<License> result = (List<License>) query.execute(licenseId);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Creates a new License.
     * @param license the License object to create
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a created License object
     */
    public License createLicense(License license, boolean commitIndex) {
        final License result = persist(license);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, License.class);
        return result;
    }

    /**
     * Updates a license.
     * @param transientLicense the license to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a License object
     */
    public License updateLicense(License transientLicense, boolean commitIndex) {
        final License license;
        if (transientLicense.getId() > 0) {
            license = getObjectById(License.class, transientLicense.getId());
        } else {
            license = getLicense(transientLicense.getLicenseId());
        }

        if (license != null) {
            license.setLicenseId(transientLicense.getLicenseId());
            license.setName(transientLicense.getName());
            license.setText(transientLicense.getText());
            license.setHeader(transientLicense.getHeader());
            license.setTemplate(transientLicense.getTemplate());
            license.setOsiApproved(transientLicense.isOsiApproved());
            license.setDeprecatedLicenseId(transientLicense.isDeprecatedLicenseId());
            license.setComment(transientLicense.getComment());
            license.setSeeAlso(transientLicense.getSeeAlso());

            final License result = persist(license);
            Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, License.class);
            return result;
        }
        return null;
    }

    /**
     * Synchronize a License, updating it if it needs updating, or creating it if it doesn't exist.
     * @param license the License object to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a synchronize License object
     */
    public License synchronizeLicense(License license, boolean commitIndex) {
        License result = updateLicense(license, commitIndex);
        if (result == null) {
            result = createLicense(license, commitIndex);
        }
        return result;
    }

    /**
     * Creates a new Vulnerability.
     * @param vulnerability the vulnerability to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new vulnerability object
     */
    public Vulnerability createVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        final Vulnerability result = persist(vulnerability);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Vulnerability.class);
        return result;
    }

    /**
     * Updates a vulnerability.
     * @param transientVulnerability the vulnerability to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Vulnerability object
     */
    public Vulnerability updateVulnerability(Vulnerability transientVulnerability, boolean commitIndex) {
        final Vulnerability vulnerability;
        if (transientVulnerability.getId() > 0) {
            vulnerability = getObjectById(Vulnerability.class, transientVulnerability.getId());
        } else {
            vulnerability = getVulnerabilityByVulnId(transientVulnerability.getSource(), transientVulnerability.getVulnId());
        }

        if (vulnerability != null) {
            vulnerability.setCreated(transientVulnerability.getCreated());
            vulnerability.setPublished(transientVulnerability.getPublished());
            vulnerability.setUpdated(transientVulnerability.getUpdated());
            vulnerability.setVulnId(transientVulnerability.getVulnId());
            vulnerability.setSource(transientVulnerability.getSource());
            vulnerability.setCredits(transientVulnerability.getCredits());
            vulnerability.setVulnerableVersions(transientVulnerability.getVulnerableVersions());
            vulnerability.setPatchedVersions(transientVulnerability.getPatchedVersions());
            vulnerability.setDescription(transientVulnerability.getDescription());
            vulnerability.setTitle(transientVulnerability.getTitle());
            vulnerability.setSubTitle(transientVulnerability.getSubTitle());
            vulnerability.setReferences(transientVulnerability.getReferences());
            vulnerability.setRecommendation(transientVulnerability.getRecommendation());
            vulnerability.setCwe(transientVulnerability.getCwe());
            vulnerability.setCvssV2Vector(transientVulnerability.getCvssV2Vector());
            vulnerability.setCvssV2BaseScore(transientVulnerability.getCvssV2BaseScore());
            vulnerability.setCvssV2ImpactSubScore(transientVulnerability.getCvssV2ImpactSubScore());
            vulnerability.setCvssV2ExploitabilitySubScore(transientVulnerability.getCvssV2ExploitabilitySubScore());
            vulnerability.setCvssV3Vector(transientVulnerability.getCvssV3Vector());
            vulnerability.setCvssV3BaseScore(transientVulnerability.getCvssV3BaseScore());
            vulnerability.setCvssV3ImpactSubScore(transientVulnerability.getCvssV3ImpactSubScore());
            vulnerability.setCvssV3ExploitabilitySubScore(transientVulnerability.getCvssV3ExploitabilitySubScore());
            vulnerability.setMatchedAllPreviousCPE(transientVulnerability.getMatchedAllPreviousCPE());
            vulnerability.setMatchedCPE(transientVulnerability.getMatchedCPE());

            final Vulnerability result = persist(vulnerability);
            Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, Vulnerability.class);
            return result;
        }
        return null;
    }

    /**
     * Synchronizes a vulnerability. Method first checkes to see if the vulnerability already
     * exists and if so, updates the vulnerability. If the vulnerability does not already exist,
     * this method will create a new vulnerability.
     * @param vulnerability the vulnerability to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Vulnerability object
     */
    public Vulnerability synchronizeVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        Vulnerability result = updateVulnerability(vulnerability, commitIndex);
        if (result == null) {
            result = createVulnerability(vulnerability, commitIndex);
        }
        return result;
    }

    /**
     * Returns a vulnerability by it's name (i.e. CVE-2017-0001) and source.
     * @param source the source of the vulnerability
     * @param vulnId the name of the vulnerability
     * @return the matching Vulnerability object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Vulnerability getVulnerabilityByVulnId(String source, String vulnId) {
        final Query query = pm.newQuery(Vulnerability.class, "source == :source && vulnId == :vulnId");
        query.getFetchPlan().addGroup(Vulnerability.FetchGroup.COMPONENTS.name());
        final List<Vulnerability> result = (List<Vulnerability>) query.execute(source, vulnId);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns a vulnerability by it's name (i.e. CVE-2017-0001) and source.
     * @param source the source of the vulnerability
     * @param vulnId the name of the vulnerability
     * @return the matching Vulnerability object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Vulnerability getVulnerabilityByVulnId(Vulnerability.Source source, String vulnId) {
        return getVulnerabilityByVulnId(source.name(), vulnId);
    }

    /**
     * Returns vulnerabilities for the specified npm module
     * @param module the NPM module to query on
     * @return a list of Vulnerability objects
     */
    /** todo: determine if this is needed and delete */
    @Deprecated
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getVulnerabilitiesForNpmModule(String module) {
        final Query query = pm.newQuery(Vulnerability.class, "source == :source && subtitle == :module");
        query.getFetchPlan().addGroup(Vulnerability.FetchGroup.COMPONENTS.name());
        return (List<Vulnerability>) query.execute(Vulnerability.Source.NSP.name(), module);
    }

    /**
     * Adds a vulnerability to a component.
     * @param vulnerability the vulnerabillity to add
     * @param component the component affected by the vulnerabiity
     */
    @SuppressWarnings("unchecked")
    public void addVulnerability(Vulnerability vulnerability, Component component) {
        vulnerability = getObjectById(Vulnerability.class, vulnerability.getId());
        component = getObjectById(Component.class, component.getId());
        if (!contains(vulnerability, component)) {
            pm.currentTransaction().begin();
            component.addVulnerability(vulnerability);
            pm.currentTransaction().commit();
        }
    }

    /**
     * Removes a vulnerability from a component.
     * @param vulnerability the vulnerabillity to remove
     * @param component the component unaffected by the vulnerabiity
     */
    @SuppressWarnings("unchecked")
    public void removeVulnerability(Vulnerability vulnerability, Component component) {
        vulnerability = getObjectById(Vulnerability.class, vulnerability.getId());
        component = getObjectById(Component.class, component.getId());
        if (contains(vulnerability, component)) {
            pm.currentTransaction().begin();
            component.removeVulnerability(vulnerability);
            pm.currentTransaction().commit();
        }
    }

    /**
     * Determines if a Component is affected by a specific Vulnerability by checking
     * {@link Vulnerability#getSource()} and {@link Vulnerability#getVulnId()}.
     * @param vulnerability The vulnerability to check if associated with component
     * @param component The component to check against
     * @return true if vulnerability is associated with the component, false if not
     */
    public boolean contains(Vulnerability vulnerability, Component component) {
        vulnerability = getObjectById(Vulnerability.class, vulnerability.getId());
        component = getObjectById(Component.class, component.getId());
        for (Vulnerability vuln: component.getVulnerabilities()) {
            if (vuln.getSource() != null && vuln.getSource().equals(vulnerability.getSource())
                    && vuln.getVulnId() != null && vuln.getVulnId().equals(vulnerability.getVulnId())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the specified CWE id exists or not. If not, creates
     * a new CWE with the specified ID and name. In both cases, the
     * CWE will be returned.
     * @param id the CWE ID
     * @param name the name of the CWE
     * @return a CWE object
     */
    public Cwe createCweIfNotExist(int id, String name) {
        Cwe cwe = getCweById(id);
        if (cwe != null) {
            return cwe;
        }
        cwe = new Cwe();
        cwe.setCweId(id);
        cwe.setName(name);
        return persist(cwe);
    }

    /**
     * Returns a CWE by it's CWE-ID.
     * @param cweId the CWE-ID
     * @return a CWE object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Cwe getCweById(int cweId) {
        final Query query = pm.newQuery(Cwe.class, "cweId == :cweId");
        final List<Cwe> result = (List<Cwe>) query.execute(cweId);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns a complete list of all CWE's.
     * @return a List of CWEs
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getCwes() {
        final Query query = pm.newQuery(Cwe.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("cweId == :cweId || name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filter, filterString);
        }
        return execute(query);
    }

    /**
     * Checks if the specified Dependency exists or not. If not, creates
     * a new Dependency with the specified project and component. In both
     * cases, the Dependency will be returned.
     * @param project the Project
     * @param component the Component
     * @param addedBy optional string representation of a username
     * @param notes any notes on why the dependency exists or its usage
     * @return a Dependency object
     */
    public Dependency createDependencyIfNotExist(Project project, Component component, String addedBy, String notes) {
        List<Dependency> dependencies = getDependencies(project, component);

        // Holder for possible duplicate dependencies
        List<Dependency> duplicates = new ArrayList<>();

        // Holder for an existing Dependency (if present)
        Dependency existingDependency = null;

        if (dependencies.size() > 0) {
            // Ensure that only one dependency object exists
            if (dependencies.size() > 1) {
                // Iterate through the duplicates and add them to the list of dependencies to be deleted
                for (int i = 1; i < dependencies.size(); i++) {
                    duplicates.add(dependencies.get(i));
                }
            }
            // Return the first dependency found - all others will be deleted
            existingDependency = dependencies.get(0);
        }
        delete(duplicates);

        if (existingDependency != null) {
            return existingDependency;
        }

        Dependency dependency = getDependency(project, component);
        if (dependency != null) {
            return dependency;
        }
        dependency = new Dependency();
        dependency.setProject(project);
        dependency.setComponent(component);
        dependency.setAddedBy(addedBy);
        dependency.setAddedOn(new Date());
        dependency.setNotes(notes);
        dependency = persist(dependency);
        NotificationUtil.analyzeNotificationCriteria(this, dependency);
        return dependency;
    }

    /**
     * Checks if the specified Dependency exists or not. If so, removes
     * the component as a dependency of the project.
     * @param project the Project
     * @param component the Component
     */
    public void removeDependencyIfExist(Project project, Component component) {
        Dependency dependency = getDependency(project, component);
        if (dependency != null) {
            delete(dependency);
        }
    }

    /**
     * Intelligently adds dependencies for components that are not already a dependency
     * of the specified project and removes the dependency relationship for components
     * that are not in the list of specified components.
     * @param project the project to bind components to
     * @param components the complete list of components that should be dependencies of the project
     */
    public void reconcileDependencies(Project project, List<Component> components) {
        // Holds a list of all Components that are existing dependencies of the specified project
        final List<Component> existingProjectDependencies = new ArrayList<>();
        getAllDependencies(project).forEach(item -> existingProjectDependencies.add(item.getComponent()));
        reconcileDependencies(project, existingProjectDependencies, components);
    }

    /**
     * Intelligently adds dependencies for components that are not already a dependency
     * of the specified project and removes the dependency relationship for components
     * that are not in the list of specified components.
     * @param project the project to bind components to
     * @param existingProjectDependencies the complete list of existing dependent components
     * @param components the complete list of components that should be dependencies of the project
     */
    public void reconcileDependencies(Project project, List<Component> existingProjectDependencies, List<Component> components) {
        // Removes components as dependencies to the project for all
        // components not included in the list provided
        for (Component existingDependency: existingProjectDependencies) {
            boolean keep = false;
            for (Component component: components) {
                if (component.getId() == existingDependency.getId()) {
                    keep = true;
                }
            }
            if (!keep) {
                removeDependencyIfExist(project, existingDependency);
            }
        }
        components.forEach(component -> createDependencyIfNotExist(project, component, null, null));
    }

    /**
     * Returns a List of all Dependency for the specified Project.
     * This method if designed NOT to provide paginated results.
     * @param project the Project to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public List<Dependency> getAllDependencies(Project project) {
        final Query query = pm.newQuery(Dependency.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        query.getFetchPlan().addGroup(Dependency.FetchGroup.COMPONENT_ONLY.name());
        query.setOrdering("component.name asc");
        return (List<Dependency>)query.execute(project);
    }

    /**
     * Returns a List of Dependency for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getDependencies(Project project) {
        final Query query = pm.newQuery(Dependency.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        query.getFetchPlan().addGroup(Dependency.FetchGroup.COMPONENT_ONLY.name());
        query.setOrdering("component.name asc");
        if (filter != null) {
            query.setFilter("project == :project && component.name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, project, filterString);
        }
        return execute(query, project);
    }

    /**
     * Returns a List of Dependency for the specified Component.
     * @param component the Component to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getDependencies(Component component) {
        final Query query = pm.newQuery(Dependency.class, "component == :component");
        query.setOrdering("id asc");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.PROJECT_ONLY.name());
        return execute(query, component);
    }

    /**
     * Returns a List of Dependency for the specified Component.
     * This method if designed NOT to provide paginated results.
     * @param component the Component to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public List<Dependency> getAllDependencies(Component component) {
        component = getObjectById(Component.class, component.getId());
        final Query query = pm.newQuery(Dependency.class, "component == :component");
        query.setOrdering("id asc");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.PROJECT_ONLY.name());
        return (List<Dependency>)query.execute(component);
    }

    /**
     * Deletes all dependencies for the specified Project.
     * @param project the Project to delete dependencies of
     */
    @SuppressWarnings("unchecked")
    public void deleteDependencies(Project project) {
        final Query query = pm.newQuery(Dependency.class, "project == :project");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.PROJECT_ONLY.name());
        query.deletePersistentAll(project);
    }

    /**
     * Deletes all dependencies for the specified Component.
     * @param component the Component to delete dependencies of
     */
    @SuppressWarnings("unchecked")
    public void deleteDependencies(Component component) {
        final Query query = pm.newQuery(Dependency.class, "component == :component");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.COMPONENT_ONLY.name());
        query.deletePersistentAll(component);
    }

    /**
     * Returns the number of Dependency objects for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return the total number of dependencies for the project
     */
    @SuppressWarnings("unchecked")
    public long getDependencyCount(Project project) {
        final Query query = pm.newQuery(Dependency.class, "project == :project");
        return getCount(query, project);
    }

    /**
     * Returns the number of Dependency objects for the specified Component.
     * @param component the Component to retrieve dependencies of
     * @return the total number of dependencies for the component
     */
    @SuppressWarnings("unchecked")
    public long getDependencyCount(Component component) {
        final Query query = pm.newQuery(Dependency.class, "component == :component");
        return getCount(query, component);
    }

    /**
     * Returns a Dependency for the specified Project and Component.
     * @param project the Project the component is part of
     * @param component the Component
     * @return a Dependency object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Dependency getDependency(Project project, Component component) {
        final List<Dependency> result = getDependencies(project, component);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns a List of Dependencies for the specified Project and Component.
     *
     * There should NEVER be duplicate dependencies. But this method is intended
     * to check for them and return the list. This is a private method and should
     * never be accessed outside the QueryManager.
     *
     * @param project the Project the component is part of
     * @param component the Component
     * @return a List of Dependency objects, or null if not found
     */
    @SuppressWarnings("unchecked")
    private List<Dependency> getDependencies(Project project, Component component) {
        final Query query = pm.newQuery(Dependency.class, "project == :project && component == :component");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.ALL.name());
        return (List<Dependency>) query.execute(project, component);
    }

    /**
     * Returns a fully refreshed Dependency object with all fetch groups returned.
     *
     * @param dependency the dependency to fully refresh
     * @return a Dependency object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Dependency getDependency(Dependency dependency) {
        final Query query = pm.newQuery(Dependency.class, "id == :id");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.ALL.name());
        final List<Dependency> result = (List<Dependency>) query.execute(dependency.getId());
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns a List of all Vulnerabilities.
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getVulnerabilities() {
        final Query query = pm.newQuery(Vulnerability.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("vulnId.toLowerCase().matches(:vulnId)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of Vulnerability for the specified Component and excludes suppressed vulnerabilities.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getVulnerabilities(Component component) {
        return getVulnerabilities(component, false);
    }

    /**
     * Returns a List of Vulnerability for the specified Component.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getVulnerabilities(Component component, boolean includeSuppressed) {
        String filter = (includeSuppressed) ? "components.contains(:component)" : "components.contains(:component)" + generateExcludeSuppressed(component);
        final Query query = pm.newQuery(Vulnerability.class, filter);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        return execute(query, component);
    }

    /**
     * Returns a List of Vulnerability for the specified Component and excludes suppressed vulnerabilities.
     * This method if designed NOT to provide paginated results.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getAllVulnerabilities(Component component) {
        return getAllVulnerabilities(component, false);
    }

    /**
     * Returns a List of Vulnerability for the specified Component.
     * This method if designed NOT to provide paginated results.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getAllVulnerabilities(Component component, boolean includeSuppressed) {
        String filter = (includeSuppressed) ? "components.contains(:component)" : "components.contains(:component)" + generateExcludeSuppressed(component);
        final Query query = pm.newQuery(Vulnerability.class, filter);
        return (List<Vulnerability>)query.execute(component);
    }

    /**
     * Returns a List of Vulnerability for the specified Dependency and excludes suppressed vulnerabilities.
     * This method if designed NOT to provide paginated results.
     * @param dependency the Dependency to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getAllVulnerabilities(Dependency dependency) {
        return getAllVulnerabilities(dependency, false);
    }

    /**
     * Returns a List of Vulnerability for the specified Dependency.
     * This method if designed NOT to provide paginated results.
     * @param dependency the Dependency to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getAllVulnerabilities(Dependency dependency, boolean includeSuppressed) {
        final String filter;
        if (includeSuppressed) {
            filter = "components.contains(:component)";
        } else {
            filter = "components.contains(:component)" + generateExcludeSuppressed(
                    dependency.getProject(), dependency.getComponent()
            );
        }
        final Query query = pm.newQuery(Vulnerability.class, filter);
        return (List<Vulnerability>)query.execute(dependency.getComponent());
    }

    /**
     * Returns the number of Vulnerability objects for the specified Project.
     * @param project the Project to retrieve vulnerabilities of
     * @return the total number of vulnerabilities for the project
     */
    @SuppressWarnings("unchecked")
    public long getVulnerabilityCount(Project project, boolean includeSuppressed) {
        long total = 0;
        long suppressed = 0;
        final List<Dependency> dependencies = getAllDependencies(project);
        for (Dependency dependency: dependencies) {
            total += getCount(pm.newQuery(Vulnerability.class, "components.contains(:component)"), dependency.getComponent());
            if (! includeSuppressed) {
                suppressed += getSuppressedCount(dependency.getComponent()); // account for globally suppressed components
                suppressed += getSuppressedCount(project, dependency.getComponent()); // account for per-project/component
            }
        }
        return total - suppressed;
    }

    /**
     * Returns a List of Vulnerability for the specified Project.
     * This method is unique and used by third-party integrations
     * such as ThreadFix for the retrieval of vulnerabilities from
     * a specific project along with the affected component(s).
     * @param project the Project to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getVulnerabilities(Project project) {
        final List<Vulnerability> vulnerabilities = new ArrayList<>();
        final List<Dependency> dependencies = getAllDependencies(project);
        for (Dependency dependency: dependencies) {
            final Collection<Vulnerability> componentVulns = pm.detachCopyAll(
                    getAllVulnerabilities(dependency.getComponent())
            );
            for (Vulnerability componentVuln: componentVulns) {
                componentVuln.setComponents(Arrays.asList(pm.detachCopy(dependency.getComponent())));
            }
            vulnerabilities.addAll(componentVulns);
        }
        return vulnerabilities;
    }

    /**
     * Returns the number of suppressed vulnerabilities for the portfolio.
     * @return the total number of suppressed vulnerabilities
     */
    @SuppressWarnings("unchecked")
    public long getSuppressedCount() {
        final Query query = pm.newQuery(Analysis.class, "suppressed == true");
        return getCount(query);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Project
     * @param project the Project to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the project / component
     */
    @SuppressWarnings("unchecked")
    public long getSuppressedCount(Project project) {
        final Query query = pm.newQuery(Analysis.class, "project == :project && suppressed == true");
        return getCount(query, project);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Component.
     * @param component the Component to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the component
     */
    @SuppressWarnings("unchecked")
    public long getSuppressedCount(Component component) {
        final Query query = pm.newQuery(Analysis.class, "project == null && component == :component && suppressed == true");
        return getCount(query, component);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Project / Component.
     * @param project the Project to retrieve suppressed vulnerabilities of
     * @param component the Component to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the project / component
     */
    @SuppressWarnings("unchecked")
    public long getSuppressedCount(Project project, Component component) {
        final Query query = pm.newQuery(Analysis.class, "project == :project && component == :component && suppressed == true");
        return getCount(query, project, component);
    }

    /**
     * Generates partial JDOQL statement excluding suppressed vulnerabilities for this component (global).
     * @param component the component to query on
     * @return a partial where clause
     */
    @SuppressWarnings("unchecked")
    private String generateExcludeSuppressed(Component component) {
        return generateExcludeSuppressed(null, component);
    }

    /**
     * Generates partial JDOQL statement excluding suppressed vulnerabilities for this project.
     * @param project the project to query on
     * @return a partial where clause
     */
    @SuppressWarnings("unchecked")
    private String generateExcludeSuppressed(Project project) {
        return generateExcludeSuppressed(project, null);
    }

    /**
     * Generates partial JDOQL statement excluding suppressed vulnerabilities for this project/component
     * and for globally suppressed vulnerabilities against the specified component.
     * @param component the component to query on
     * @param project the project to query on
     * @return a partial where clause
     */
    @SuppressWarnings("unchecked")
    private String generateExcludeSuppressed(Project project, Component component) {
        // Retrieve a list of all suppressed vulnerabilities
        final Query analysisQuery = pm.newQuery(Analysis.class, "(project == :project || project == null) && component == :component && suppressed == true");
        List<Analysis> analysisList = (List<Analysis>)analysisQuery.execute(project, component);
        // Construct exclude clause based on above results
        String excludeClause = analysisList.stream().map(analysis -> "id != " + analysis.getVulnerability().getId() + " && ").collect(Collectors.joining());
        if (StringUtils.trimToNull(excludeClause) != null) {
            excludeClause = " && (" + excludeClause.substring(0, excludeClause.lastIndexOf(" && ")) + ")";
        }
        return excludeClause;
    }

    /**
     * Returns a List of Projects affected by a specific vulnerability.
     * @param vulnerability the vulnerability to query on
     * @return a List of Projects
     */
    @SuppressWarnings("unchecked")
    public List<Project> getProjects(Vulnerability vulnerability) {
        final List<Project> projects = new ArrayList<>();
        for (Component component: vulnerability.getComponents()) {
            for (Dependency dependency: getAllDependencies(component)) {
                boolean affected = true;
                Analysis globalAnalysis = getAnalysis(null, component, vulnerability);
                Analysis projectAnalysis = getAnalysis(dependency.getProject(), component, vulnerability);
                if (globalAnalysis != null && globalAnalysis.isSuppressed()) {
                    affected = false;
                }
                if (projectAnalysis != null && projectAnalysis.isSuppressed()) {
                    affected = false;
                }
                if (affected) {
                    projects.add(dependency.getProject());
                }
            }
        }
        // Force removal of duplicates by taking the List and populating a Set and back again.
        final Set<Project> set = new LinkedHashSet<>(projects);
        projects.clear();
        projects.addAll(set);
        return projects;
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     * @param project the Project
     * @param component the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Analysis getAnalysis(Project project, Component component, Vulnerability vulnerability) {
        final Query query = pm.newQuery(Analysis.class, "project == :project && component == :component && vulnerability == :vulnerability");
        final List<Analysis> result = (List<Analysis>) query.execute(project, component, vulnerability);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Documents a new analysis. Creates a new Analysis object if one doesn't already exists and appends
     * the specified comment along with a timestamp in the AnalysisComment trail.
     * @param project the Project
     * @param component the Component
     * @param vulnerability the Vulnerability
     * @return an Analysis object
     */
    public Analysis makeAnalysis(Project project, Component component, Vulnerability vulnerability,
                                 AnalysisState analysisState, Boolean isSuppressed) {
        if (analysisState == null) {
            analysisState = AnalysisState.NOT_SET;
        }
        Analysis analysis = getAnalysis(project, component, vulnerability);
        if (analysis == null) {
            analysis = new Analysis();
            analysis.setProject(project);
            analysis.setComponent(component);
            analysis.setVulnerability(vulnerability);
        }
        if (isSuppressed != null) {
            analysis.setSuppressed(isSuppressed);
        }
        analysis.setAnalysisState(analysisState);
        analysis = persist(analysis);
        return getAnalysis(analysis.getProject(), analysis.getComponent(), analysis.getVulnerability());
    }

    /**
     * Adds a new analysis comment to the specified analysis.
     * @param analysis the analysis object to add a comment to
     * @param comment the comment to make
     * @param commenter the name of the principal who wrote the comment
     * @return a new AnalysisComment object
     */
    public AnalysisComment makeAnalysisComment(Analysis analysis, String comment, String commenter) {
        if (analysis == null || comment == null) {
            return null;
        }
        AnalysisComment analysisComment = new AnalysisComment();
        analysisComment.setAnalysis(analysis);
        analysisComment.setTimestamp(new Date());
        analysisComment.setComment(comment);
        analysisComment.setCommenter(commenter);
        return persist(analysisComment);
    }

    /**
     * Deleted all analysis and comments associated for the specified Component.
     * @param component the Component to delete analysis for
     */
    public void deleteAnalysisTrail(Component component) {
        final Query query = pm.newQuery(Analysis.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all analysis and comments associated for the specified Project.
     * @param project the Project to delete analysis for
     */
    public void deleteAnalysisTrail(Project project) {
        final Query query = pm.newQuery(Analysis.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Returns a List of Finding objects for the specified project.
     * @param project the project to retrieve findings for
     * @return a List of Finding objects
     */
    @SuppressWarnings("unchecked")
    public List<Finding> getFindings(Project project) {
        Query query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, Finding.QUERY);
        query.setParameters(project.getId());
        List<Object[]> list = query.executeList();
        List<Finding> findings = new ArrayList<>();
        for (Object[] o: list) {
            Finding finding = new Finding(o);
            Component component = getObjectByUuid(Component.class, (String)finding.getComponentUuid());
            Vulnerability vulnerability = getObjectByUuid(Vulnerability.class, (String)finding.getVulnUuid());
            Analysis analysis = getAnalysis(null, component, vulnerability);
            if (analysis == null || !analysis.isSuppressed()) { // do not add globally suppressed findings
                findings.add(finding);
            }
        }
        return findings;
    }

    /**
     * Retrieves the current VulnerabilityMetrics
     * @return a VulnerabilityMetrics object
     */
    @SuppressWarnings("unchecked")
    public List<VulnerabilityMetrics> getVulnerabilityMetrics() {
        final Query query = pm.newQuery(VulnerabilityMetrics.class);
        query.setOrdering("year asc, month asc");
        return execute(query).getList(VulnerabilityMetrics.class);
    }

    /**
     * Retrieves the most recent PortfolioMetrics.
     * @return a PortfolioMetrics object
     */
    @SuppressWarnings("unchecked")
    public PortfolioMetrics getMostRecentPortfolioMetrics() {
        final Query query = pm.newQuery(PortfolioMetrics.class);
        query.setOrdering("lastOccurrence desc");
        final List<PortfolioMetrics> result = execute(query).getList(PortfolioMetrics.class);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Retrieves PortfolioMetrics in descending order starting with the most recent.
     * @return a PaginatedResult object
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPortfolioMetrics() {
        final Query query = pm.newQuery(PortfolioMetrics.class);
        query.setOrdering("lastOccurrence desc");
        return execute(query);
    }

    /**
     * Retrieves PortfolioMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<PortfolioMetrics> getPortfolioMetricsSince(Date since) {
        final Query query = pm.newQuery(PortfolioMetrics.class, "lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<PortfolioMetrics>)query.execute(since);
    }

    /**
     * Retrieves the most recent ProjectMetrics.
     * @param project the Project to retrieve metrics for
     * @return a ProjectMetrics object
     */
    @SuppressWarnings("unchecked")
    public ProjectMetrics getMostRecentProjectMetrics(Project project) {
        final Query query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.setOrdering("lastOccurrence desc");
        final List<ProjectMetrics> result = execute(query, project).getList(ProjectMetrics.class);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Retrieves ProjectMetrics in descending order starting with the most recent.
     * @param project the Project to retrieve metrics for
     * @return a PaginatedResult object
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getProjectMetrics(Project project) {
        final Query query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.setOrdering("lastOccurrence desc");
        return execute(query, project);
    }

    /**
     * Retrieves ProjectMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<ProjectMetrics> getProjectMetricsSince(Project project, Date since) {
        final Query query = pm.newQuery(ProjectMetrics.class, "project == :project && lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<ProjectMetrics>)query.execute(project, since);
    }

    /**
     * Retrieves the most recent ComponentMetrics.
     * @param component the Component to retrieve metrics for
     * @return a ComponentMetrics object
     */
    @SuppressWarnings("unchecked")
    public ComponentMetrics getMostRecentComponentMetrics(Component component) {
        final Query query = pm.newQuery(ComponentMetrics.class, "component == :component");
        query.setOrdering("lastOccurrence desc");
        final List<ComponentMetrics> result = execute(query, component).getList(ComponentMetrics.class);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Retrieves ComponentMetrics in descending order starting with the most recent.
     * @param component the Component to retrieve metrics for
     * @return a PaginatedResult object
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getComponentMetrics(Component component) {
        final Query query = pm.newQuery(ComponentMetrics.class, "component == :component");
        query.setOrdering("lastOccurrence desc");
        return execute(query, component);
    }

    /**
     * Retrieves ComponentMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<ComponentMetrics> getComponentMetricsSince(Component component, Date since) {
        final Query query = pm.newQuery(ComponentMetrics.class, "component == :component && lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<ComponentMetrics>)query.execute(component, since);
    }

    /**
     * Retrieves the most recent DependencyMetrics.
     * @param dependency the Dependency to retrieve metrics for
     * @return a DependencyMetrics object
     */
    @SuppressWarnings("unchecked")
    public DependencyMetrics getMostRecentDependencyMetrics(Dependency dependency) {
        final Query query = pm.newQuery(DependencyMetrics.class, "project == :project && component == :component");
        query.setOrdering("lastOccurrence desc");
        final List<DependencyMetrics> result = execute(query, dependency.getProject(), dependency.getComponent()).getList(DependencyMetrics.class);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Retrieves DependencyMetrics in descending order starting with the most recent.
     * @param dependency the Dependency to retrieve metrics for
     * @return a PaginatedResult object
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getDependencyMetrics(Dependency dependency) {
        final Query query = pm.newQuery(DependencyMetrics.class, "project == :project && component == :component");
        query.setOrdering("lastOccurrence desc");
        return execute(query, dependency.getProject(), dependency.getComponent());
    }

    /**
     * Retrieves DependencyMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<DependencyMetrics> getDependencyMetricsSince(Dependency dependency, Date since) {
        final Query query = pm.newQuery(DependencyMetrics.class, "project == :project && component == :component && lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<DependencyMetrics>)query.execute(dependency.getProject(), dependency.getComponent(), since);
    }

    /**
     * Synchronizes VulnerabilityMetrics.
     */
    public void synchronizeVulnerabilityMetrics(VulnerabilityMetrics metric) {
        final Query query;
        final List<VulnerabilityMetrics> result;
        if (metric.getMonth() == null) {
            query = pm.newQuery(VulnerabilityMetrics.class, "year == :year && month == null");
            result = execute(query, metric.getYear()).getList(VulnerabilityMetrics.class);
        } else {
            query = pm.newQuery(VulnerabilityMetrics.class, "year == :year && month == :month");
            result = execute(query, metric.getYear(), metric.getMonth()).getList(VulnerabilityMetrics.class);
        }
        if (result.size() == 1) {
            VulnerabilityMetrics m = result.get(0);
            m.setCount(metric.getCount());
            m.setMeasuredAt(metric.getMeasuredAt());
            persist(m);
        } else if (result.size() == 0) {
            persist(metric);
        } else {
            delete(result);
            persist(metric);
        }
    }

    /**
     * Deleted all metrics associated for the specified Project.
     * @param project the Project to delete metrics for
     */
    public void deleteMetrics(Project project) {
        final Query query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.deletePersistentAll(project);

        final Query query2 = pm.newQuery(DependencyMetrics.class, "project == :project");
        query2.deletePersistentAll(project);
    }

    /**
     * Deleted all metrics associated for the specified Component.
     * @param component the Component to delete metrics for
     */
    public void deleteMetrics(Component component) {
        final Query query = pm.newQuery(ComponentMetrics.class, "component == :component");
        query.deletePersistentAll(component);

        final Query query2 = pm.newQuery(DependencyMetrics.class, "component == :component");
        query2.deletePersistentAll(component);
    }

    /**
     * Returns a list of all repositories.
     * @return a List of Repositories
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getRepositories() {
        final Query query = pm.newQuery(Repository.class);
        if (orderBy == null) {
            query.setOrdering("type asc, identifier asc");
        }
        if (filter != null) {
            query.setFilter("identifier.toLowerCase().matches(:identifier)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a list of all repositories
     * This method if designed NOT to provide paginated results.
     * @return a List of Repositories
     */
    @SuppressWarnings("unchecked")
    public List<Repository> getAllRepositories() {
        final Query query = pm.newQuery(Repository.class);
        query.setOrdering("type asc, identifier asc");
        return query.executeResultList(Repository.class);
    }

    /**
     * Returns a list of repositories by it's type.
     * @param type the type of repository (required)
     * @return a List of Repository objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getRepositories(RepositoryType type) {
        final Query query = pm.newQuery(Repository.class, "type == :type");
        if (orderBy == null) {
            query.setOrdering("identifier asc");
        }
        return execute(query, type);
    }

    /**
     * Returns a list of repositories by it's type in the order in which the repository should be used in resolution.
     * This method if designed NOT to provide paginated results.
     * @param type the type of repository (required)
     * @return a List of Repository objects
     */
    @SuppressWarnings("unchecked")
    public List<Repository> getAllRepositoriesOrdered(RepositoryType type) {
        final Query query = pm.newQuery(Repository.class, "type == :type");
        query.setOrdering("resolutionOrder asc");
        return (List<Repository>)query.execute(type);
    }

    /**
     * Creates a new Repository.
     * @param type the type of repository
     * @param identifier a unique (to the type) identifier for the repo
     * @param url the URL to the repository
     * @param enabled if the repo is enabled or not
     * @return the created Repository
     */
    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled) {
        int order = 0;
        List<Repository> existingRepos = getAllRepositoriesOrdered(type);
        if (existingRepos != null) {
            for (Repository existing : existingRepos) {
                if (existing.getResolutionOrder() > order) {
                    order = existing.getResolutionOrder();
                }
            }
        }
        final Repository repo = new Repository();
        repo.setType(type);
        repo.setIdentifier(identifier);
        repo.setUrl(url);
        repo.setResolutionOrder(order + 1);
        repo.setEnabled(enabled);
        return persist(repo);
    }

    /**
     * Returns a RepositoryMetaComponent object from the specified type, group, and name.
     * @param repositoryType the type of repository
     * @param namespace the Package URL namespace of the meta component
     * @param name the Package URL name of the meta component
     * @return a RepositoryMetaComponent object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public RepositoryMetaComponent getRepositoryMetaComponent(RepositoryType repositoryType, String namespace, String name) {
        final Query query = pm.newQuery(RepositoryMetaComponent.class);
        query.setFilter("repositoryType == :repositoryType && namespace == :namespace && name == :name");
        final List<RepositoryMetaComponent> result = (List<RepositoryMetaComponent>) query.execute(repositoryType, namespace, name);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Synchronizes a RepositoryMetaComponent, updating it if it needs updating, or creating it if it doesn't exist.
     * @param repositoryMetaComponent the RepositoryMetaComponent object to synchronize
     * @return a synchronized RepositoryMetaComponent object
     */
    public RepositoryMetaComponent synchronizeRepositoryMetaComponent(RepositoryMetaComponent repositoryMetaComponent) {
        RepositoryMetaComponent result = updateRepositoryMetaComponent(repositoryMetaComponent);
        if (result == null) {
            result = persist(repositoryMetaComponent);
        }
        return result;
    }

    /**
     * Updates a RepositoryMetaComponent.
     * @param transientRepositoryMetaComponent the RepositoryMetaComponent to update
     * @return a RepositoryMetaComponent object
     */
    public RepositoryMetaComponent updateRepositoryMetaComponent(RepositoryMetaComponent transientRepositoryMetaComponent) {
        final RepositoryMetaComponent metaComponent;
        if (transientRepositoryMetaComponent.getId() > 0) {
            metaComponent = getObjectById(RepositoryMetaComponent.class, transientRepositoryMetaComponent.getId());
        } else {
            metaComponent = getRepositoryMetaComponent(transientRepositoryMetaComponent.getRepositoryType(),
                    transientRepositoryMetaComponent.getNamespace(), transientRepositoryMetaComponent.getName());
        }

        if (metaComponent != null) {
            metaComponent.setRepositoryType(transientRepositoryMetaComponent.getRepositoryType());
            metaComponent.setNamespace(transientRepositoryMetaComponent.getNamespace());
            metaComponent.setLastCheck(transientRepositoryMetaComponent.getLastCheck());
            metaComponent.setLatestVersion(transientRepositoryMetaComponent.getLatestVersion());
            metaComponent.setName(transientRepositoryMetaComponent.getName());
            metaComponent.setPublished(transientRepositoryMetaComponent.getPublished());
            return persist(metaComponent);
        }
        return null;
    }

    /**
     * Creates a new NotificationRule.
     * @param name the name of the rule
     * @param scope the scope
     * @param level the level
     * @param publisher the publisher
     * @return a new NotificationRule
     */
    public NotificationRule createNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        final NotificationRule rule = new NotificationRule();
        rule.setName(name);
        rule.setScope(scope);
        rule.setNotificationLevel(level);
        rule.setPublisher(publisher);
        rule.setEnabled(true);
        return persist(rule);
    }

    /**
     * Updated an existing NotificationRule.
     * @param transientRule the rule to update
     * @return a NotificationRule
     */
    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        final NotificationRule rule = getObjectByUuid(NotificationRule.class, transientRule.getUuid());
        rule.setName(transientRule.getName());
        rule.setNotificationLevel(transientRule.getNotificationLevel());
        rule.setPublisherConfig(transientRule.getPublisherConfig());
        rule.setNotifyOn(transientRule.getNotifyOn());
        return persist(rule);
    }

    /**
     * Returns a paginated list of all notification rules.
     * @return a paginated list of NotificationRules
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getNotificationRules() {
        final Query query = pm.newQuery(NotificationRule.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name) || publisher.name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Retrieves all NotificationPublishers.
     * This method if designed NOT to provide paginated results.
     * @return list of all NotificationPublisher objects
     */
    @SuppressWarnings("unchecked")
    public List<NotificationPublisher> getAllNotificationPublishers() {
        final Query query = pm.newQuery(NotificationPublisher.class);
        query.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
        query.setOrdering("name asc");
        return (List<NotificationPublisher>)query.execute();
    }

    /**
     * Retrieves a NotificationPublisher by its name.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    @SuppressWarnings("unchecked")
    public NotificationPublisher getNotificationPublisher(final String name) {
        final Query query = pm.newQuery(NotificationPublisher.class, "name == :name");
        final List<NotificationPublisher> result = (List<NotificationPublisher>) query.execute(name);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    @SuppressWarnings("unchecked")
    public NotificationPublisher getDefaultNotificationPublisher(final Class clazz) {
        return getDefaultNotificationPublisher(clazz.getCanonicalName());
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    @SuppressWarnings("unchecked")
    public NotificationPublisher getDefaultNotificationPublisher(final String clazz) {
        final Query query = pm.newQuery(NotificationPublisher.class, "publisherClass == :publisherClass && defaultPublisher == true");
        final List<NotificationPublisher> result = (List<NotificationPublisher>) query.execute(clazz);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Creates a NotificationPublisher object.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher createNotificationPublisher(final String name, final String description,
                                                             final Class publisherClass, final String templateContent,
                                                             final String templateMimeType, final boolean defaultPublisher) {
        pm.currentTransaction().begin();
        final NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName(name);
        publisher.setDescription(description);
        publisher.setPublisherClass(publisherClass.getCanonicalName());
        publisher.setTemplate(templateContent);
        publisher.setTemplateMimeType(templateMimeType);
        publisher.setDefaultPublisher(defaultPublisher);
        pm.makePersistent(publisher);
        pm.currentTransaction().commit();
        return getObjectById(NotificationPublisher.class, publisher.getId());
    }

    /**
     * Updates a NotificationPublisher.
     * @return a NotificationPublisher object
     */
    public NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
        NotificationPublisher publisher = null;
        if (transientPublisher.getId() > 0) {
            publisher = getObjectById(NotificationPublisher.class, transientPublisher.getId());
        } else if (transientPublisher.isDefaultPublisher()) {
            publisher = getDefaultNotificationPublisher(transientPublisher.getPublisherClass());
        }
        if (publisher != null) {
            publisher.setName(transientPublisher.getName());
            publisher.setDescription(transientPublisher.getDescription());
            publisher.setPublisherClass(transientPublisher.getPublisherClass());
            publisher.setTemplate(transientPublisher.getTemplate());
            publisher.setTemplateMimeType(transientPublisher.getTemplateMimeType());
            publisher.setDefaultPublisher(transientPublisher.isDefaultPublisher());
            return persist(publisher);
        }
        return null;
    }

    /**
     * Binds the two objects together in a corresponding join table.
     * @param project a Project object
     * @param tags a List of Tag objects
     */
    @SuppressWarnings("unchecked")
    public void bind(Project project, List<Tag> tags) {
        final Query query = pm.newQuery(Tag.class, "projects.contains(:project)");
        List<Tag> currentProjectTags = (List<Tag>)query.execute(project);
        pm.currentTransaction().begin();
        for (Tag tag: currentProjectTags) {
            if (!tags.contains(tag)) {
                tag.getProjects().remove(project);
            }
        }
        project.setTags(tags);
        for (Tag tag: tags) {
            tag.getProjects().add(project);
        }
        pm.currentTransaction().commit();
    }

    /**
     * Binds the two objects together in a corresponding join table.
     * @param scan a Scan object
     * @param component a Component object
     */
    public void bind(Scan scan, Component component) {
        boolean bound = scan.getComponents().stream().anyMatch(s -> s.getId() == scan.getId());
        if (!bound) {
            pm.currentTransaction().begin();
            scan.getComponents().add(component);
            component.getScans().add(scan);
            pm.currentTransaction().commit();
        }
    }

    /**
     * Binds the two objects together in a corresponding join table.
     * @param bom a Bom object
     * @param component a Component object
     */
    public void bind(Bom bom, Component component) {
        boolean bound = bom.getComponents().stream().anyMatch(b -> b.getId() == bom.getId());
        if (!bound) {
            pm.currentTransaction().begin();
            bom.getComponents().add(component);
            component.getBoms().add(bom);
            pm.currentTransaction().commit();
        }
    }

    /**
     * Commits the Lucene inxex.
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @param clazz the indexable class to commit the index of
     */
    public void commitSearchIndex(boolean commitIndex, Class clazz) {
        if (commitIndex) {
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, clazz));
        }
    }

    /**
     * Commits the Lucene inxex.
     * @param clazz the indexable class to commit the index of
     */
    public void commitSearchIndex(Class clazz) {
        commitSearchIndex(true, clazz);
    }
}
