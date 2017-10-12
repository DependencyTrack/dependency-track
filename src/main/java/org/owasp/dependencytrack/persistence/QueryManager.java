/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.persistence;

import alpine.Config;
import alpine.event.framework.SingleThreadedEventService;
import alpine.persistence.AlpineQueryManager;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.ComponentMetrics;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.model.Dependency;
import org.owasp.dependencytrack.model.Evidence;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.PortfolioMetrics;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectMetrics;
import org.owasp.dependencytrack.model.ProjectProperty;
import org.owasp.dependencytrack.model.Scan;
import org.owasp.dependencytrack.model.Tag;
import org.owasp.dependencytrack.model.Vulnerability;
import javax.jdo.FetchPlan;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

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
    public QueryManager() { }

    /**
     * Constructs a new QueryManager.
     * @param request an AlpineRequest object
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
    }

    /**
     * Returns a list of all projets.
     * @return a List of Projects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getProjects() {
        final Query query = pm.newQuery(Project.class);
        query.setOrdering("name asc");
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a project by it's name.
     * @param name the name of the Project
     * @return a Project object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Project getProject(String name) {
        final Query query = pm.newQuery(Project.class, "name == :name");
        final List<Project> result = (List<Project>) query.execute(name);
        return result.size() == 0 ? null : result.get(0);
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
            return null;
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
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the created Project
     */
    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent, boolean commitIndex) {
        final Project project = new Project();
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setTags(resolveTags(tags));
        if (parent != null) {
            project.setParent(parent);
        }
        final Project result = persist(project);
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
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
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the updated Project
     */
    public Project updateProject(UUID uuid, String name, String description, String version, List<Tag> tags, boolean commitIndex) {
        final Project project = getObjectByUuid(Project.class, uuid);
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setTags(resolveTags(tags));
        final Project result = persist(project);
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);
        return result;
    }

    /**
     * Deletes a Project and all objects dependant on the project.
     * @param project the Project to delete
     */
    public void recursivelyDeleteProject(Project project) {
        if (project.getChildren() != null) {
            for (Project child: project.getChildren()) {
                recursivelyDeleteProject(child);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Project result = pm.getObjectById(Project.class, project.getId());
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));

        deleteProjectMetrics(project);
        delete(project.getProperties());
        delete(getScans(project));
        delete(project.getChildren());
        delete(project);
    }

    /**
     * Creates a key/value pair (ProjectProperty) for the specified Project.
     * @param project the Project to create the property for
     * @param key the key of the property
     * @param value the value of the property
     * @return the created ProjectProperty object
     */
    public ProjectProperty createProjectProperty(Project project, String key, String value) {
        final ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setKey(key);
        property.setValue(value);
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
     * Returns a list of all Components defined in the datastore.
     * @return a List of Components
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getComponents() {
        final Query query = pm.newQuery(Component.class);
        query.setOrdering("name asc");
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a Component by its hash. Supports MD5 and SHA1 file hashes.
     * @param hash the hash of the component to retrieve
     * @return a Component, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Component getComponentByHash(String hash) {
        final Query query = pm.newQuery(Component.class, "md5 == :hash || sha1 == :hash");
        final List<Component> result = (List<Component>) query.execute(hash);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Creates a new Component.
     * @param name the name of the Component
     * @param version the optional version of the Component
     * @param group the optional group (or vendor) of the Component
     * @param filename the optional filename
     * @param md5 the optional MD5 hash
     * @param sha1 the optional SHA1 hash
     * @param description an optional description
     * @param resolvedLicense an optional resolved SPDX license
     * @param license an optional license name (text)
     * @param parent an optional parent Component
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new Component
     */
    public Component createComponent(String name, String version, String group, String filename, String md5, String sha1,
                                     String description, License resolvedLicense, String license, Component parent,
                                     boolean commitIndex) {
        final Component component = new Component();
        component.setName(name);
        component.setVersion(version);
        component.setGroup(group);
        component.setFilename(filename);
        component.setMd5(md5);
        component.setSha1(sha1);
        component.setDescription(description);
        component.setLicense(license);
        if (resolvedLicense != null) {
            resolvedLicense = getObjectById(License.class, resolvedLicense.getId());
        }
        component.setResolvedLicense(resolvedLicense);
        component.setParent(parent);
        final Component result = persist(component);
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
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
        pm.currentTransaction().begin();
        component.setName(transientComponent.getName());
        component.setVersion(transientComponent.getVersion());
        component.setGroup(transientComponent.getGroup());
        component.setFilename(transientComponent.getFilename());
        component.setMd5(transientComponent.getMd5());
        component.setSha1(transientComponent.getSha1());
        component.setDescription(transientComponent.getDescription());
        component.setLicense(transientComponent.getLicense());
        component.setResolvedLicense(transientComponent.getResolvedLicense());
        component.setParent(transientComponent.getParent());
        final Component result = persist(component);
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Component.class);
        return result;
    }

    /**
     * Deletes a Component and all objects dependant on the component.
     * @param component the Component to delete
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     */
    public void recursivelyDeleteComponent(Component component, boolean commitIndex) {
        if (component.getChildren() != null) {
            for (Component child: component.getChildren()) {
                recursivelyDeleteComponent(child, false);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Component result = pm.getObjectById(Component.class, component.getId());
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));

        //todo delete dependencies
        delete(component.getChildren());
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
        query.setOrdering("name asc");
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
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, License.class);
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
        SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
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
            SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
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
     * Returns a vulnerability by it's name (i.e. CVE-2017-0001)
     * @param vulnId the name of the vulnerability
     * @return the matching Vulnerability object, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Vulnerability getVulnerabilityByVulnId(String vulnId) {
        final Query query = pm.newQuery(Vulnerability.class, "vulnId == :vulnId");
        query.getFetchPlan().addGroup(Vulnerability.FetchGroup.COMPONENTS.name());
        final List<Vulnerability> result = (List<Vulnerability>) query.execute(vulnId);
        return result.size() == 0 ? null : result.get(0);
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
        query.setOrdering("id asc");
        if (filter != null) {
            query.setFilter("id == :id || name.toLowerCase().matches(:name)");
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
        return persist(dependency);
    }

    /**
     * Returns a List of Dependency for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getDependencies(Project project) {
        final Query query = pm.newQuery(Dependency.class, "project == :project");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.COMPONENT_ONLY.name());
        query.setOrdering("component.name asc");
        if (filter != null) {
            query.setFilter("component.name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
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
        query.getFetchPlan().addGroup(Dependency.FetchGroup.PROJECT_ONLY.name());
        return execute(query, component);
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
        final Query query = pm.newQuery(Dependency.class, "project == :project && component == :component");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.ALL.name());
        final List<Dependency> result = (List<Dependency>) query.execute(project, component);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Returns the number of total Vulnerability objects.
     * @return the total number of vulnerabilities for the component
     */
    @SuppressWarnings("unchecked")
    public long getVulnerabilityCount() {
        final Query query = pm.newQuery(Vulnerability.class);
        return getCount(query);
    }

    /**
     * Returns a List of all Vulnerabilities.
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getVulnerabilities() {
        final Query query = pm.newQuery(Vulnerability.class);
        if (orderBy == null) {
            query.setOrdering("vulnId descending, source ascending");
        }
        if (filter != null) {
            query.setFilter("vulnId.toLowerCase().matches(:vulnId)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns the number of Vulnerability objects for the specified Component.
     * @param component the Component to retrieve vulnerabilities of
     * @return the total number of vulnerabilities for the component
     */
    @SuppressWarnings("unchecked")
    public long getVulnerabilityCount(Component component) {
        final Query query = pm.newQuery(Vulnerability.class, "components.contains(:component)");
        return getCount(query, component);
    }

    /**
     * Returns a List of Vulnerability for the specified Component.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getVulnerabilities(Component component) {
        final Query query = pm.newQuery(Vulnerability.class, "components.contains(:component)");
        return execute(query, component);
    }

    /**
     * Returns the number of Vulnerability objects for the specified Project.
     * @param project the Project to retrieve vulnerabilities of
     * @return the total number of vulnerabilities for the project
     */
    @SuppressWarnings("unchecked")
    public long getVulnerabilityCount(Project project) {
        long total = 0;
        final List<Dependency> dependencies = getDependencies(project).getList(Dependency.class);
        for (Dependency dependency: dependencies) {
            total += getVulnerabilityCount(dependency.getComponent());
        }
        return total;
    }

    /**
     * Returns a List of Vulnerability for the specified Project.
     * @param project the Project to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    public List<Vulnerability> getVulnerabilities(Project project) {
        final List<Vulnerability> vulnerabilities = new ArrayList<>();
        final List<Dependency> dependencies = getDependencies(project).getList(Dependency.class);
        for (Dependency dependency: dependencies) {
            vulnerabilities.addAll(getVulnerabilities(dependency.getComponent()).getObjects());
        }
        return vulnerabilities;
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
            for (Dependency dependency: getDependencies(component).getList(Dependency.class)) {
                projects.add(dependency.getProject());
            }
        }
        return projects;
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
     * Deleted all metrics associated for the specified Project.
     * @param project the Project to delete metrics for
     */
    public void deleteProjectMetrics(Project project) {
        final Query query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.deletePersistentAll(project);
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
     * Binds the two objects together in a corresponding join table.
     * @param scan a Scan object
     * @param component a Component object
     */
    public void bind(Scan scan, Component component) {
        pm.currentTransaction().begin();
        scan.getComponents().add(component);
        component.getScans().add(scan);
        pm.currentTransaction().commit();
    }

    /**
     * Binds the two objects together in a corresponding join table.
     * @param component a Component object
     * @param vulnerability a Vulnerability object
     */
    public void bind(Component component, Vulnerability vulnerability) {
        pm.currentTransaction().begin();
        vulnerability.getComponents().add(component);
        component.getVulnerabilities().add(vulnerability);
        pm.currentTransaction().commit();
    }

    /**
     * Commits the Lucene inxex.
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @param clazz the indexable class to commit the index of
     */
    public void commitSearchIndex(boolean commitIndex, Class clazz) {
        if (commitIndex) {
            SingleThreadedEventService.getInstance().publish(new IndexEvent(IndexEvent.Action.COMMIT, clazz));
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
