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
import alpine.resources.AlpineRequest;
import org.owasp.dependencytrack.event.IndexAddEvent;
import org.owasp.dependencytrack.event.IndexDeleteEvent;
import org.owasp.dependencytrack.event.IndexUpdateEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.model.Dependency;
import org.owasp.dependencytrack.model.Evidence;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectProperty;
import org.owasp.dependencytrack.model.Scan;
import org.owasp.dependencytrack.model.Tag;
import org.owasp.dependencytrack.model.Vulnerability;
import javax.jdo.FetchPlan;
import javax.jdo.Query;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * This QueryManager provides a concrete extension of {@link AlpineQueryManager} by
 * providing methods that operate on the Dependency-Track specific models.
 *
 * @author Steve Springett
 * @since 1.0.0
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
    public List<Project> getProjects() {
        final Query query = pm.newQuery(Project.class);
        query.setOrdering("name asc");
        return (List<Project>) execute(query);
    }

    /**
     * Returns a project by it's name
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
            final Tag resolvedTag = getTagByName(tag.getName());
            if (resolvedTag != null) {
                resolvedTags.add(resolvedTag);
            } else {
                unresolvedTags.add(tag.getName());
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
        final Query query = pm.newQuery(Tag.class, "name == :name");
        final List<Tag> result = (List<Tag>) query.execute(name);
        return result.size() == 0 ? null : result.get(0);
    }

    /**
     * Creates a new Tag object with the specified name.
     * @param name the name of the Tag to create
     * @return the created Tag object
     */
    public Tag createTag(String name) {
        final Tag resolvedTag = getTagByName(name);
        if (resolvedTag != null) {
            return resolvedTag;
        }
        final Tag tag = new Tag();
        tag.setName(name);
        pm.currentTransaction().begin();
        pm.makePersistent(tag);
        pm.currentTransaction().commit();
        return pm.getObjectById(Tag.class, tag.getId());
    }

    /**
     * Creates one or more Tag objects from the specified name(s).
     * @param names the name(s) of the Tag(s) to create
     * @return the created Tag object(s)
     */
    public List<Tag> createTags(List<String> names) {
        final List<Tag> newTags = new ArrayList<>();
        for (String name: names) {
            if (getTagByName(name) == null) {
                final Tag tag = new Tag();
                tag.setName(name);
                newTags.add(tag);
            }
        }
        pm.currentTransaction().begin();
        pm.makePersistentAll(newTags);
        pm.currentTransaction().commit();
        return newTags;
    }

    /**
     * Creates a new Project.
     * @param name the name of the project to create
     * @param description a description of the project
     * @param version the project version
     * @param tags a List of Tags - these will be resolved if necessary
     * @param parent an optional parent Project
     * @return the created Project
     */
    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent) {
        final Project project = new Project();
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setUuid(UUID.randomUUID().toString());
        project.setTags(resolveTags(tags));
        if (parent != null) {
            project.setParent(parent);
        }
        pm.currentTransaction().begin();
        pm.makePersistent(project);
        pm.currentTransaction().commit();
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Project result = pm.getObjectById(Project.class, project.getId());
        SingleThreadedEventService.getInstance().publish(new IndexAddEvent(pm.detachCopy(result)));
        return result;
    }

    /**
     * Updates an existing Project.
     * @param transientProject the project to update
     * @return the updated Project
     */
    public Project updateProject(Project transientProject) {
        final Project project = getObjectByUuid(Project.class, transientProject.getUuid());
        pm.currentTransaction().begin();
        project.setName(transientProject.getName());
        project.setVersion(transientProject.getVersion());
        pm.currentTransaction().commit();
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Project result = pm.getObjectById(Project.class, project.getId());
        SingleThreadedEventService.getInstance().publish(new IndexUpdateEvent(pm.detachCopy(result)));
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
        SingleThreadedEventService.getInstance().publish(new IndexDeleteEvent(pm.detachCopy(result)));

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
        pm.currentTransaction().begin();
        pm.makePersistent(property);
        pm.currentTransaction().commit();
        return pm.getObjectById(ProjectProperty.class, property.getId());
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
        scan.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(scan);
        pm.currentTransaction().commit();
        return pm.getObjectById(Scan.class, scan.getId());
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
    public List<Component> getComponents() {
        final Query query = pm.newQuery(Component.class);
        query.setOrdering("name asc");
        return (List<Component>) execute(query);
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
     * @return a new Component
     */
    public Component createComponent(String name, String version, String group, String filename, String md5, String sha1,
                                     String description, License resolvedLicense, String license, Component parent) {
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
        component.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(component);
        pm.currentTransaction().commit();

        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Component result = pm.getObjectById(Component.class, component.getId());
        SingleThreadedEventService.getInstance().publish(new IndexAddEvent(pm.detachCopy(result)));
        return result;
    }

    /**
     * Updated an existing Component.
     * @param transientComponent the component to update
     * @return a Component
     */
    public Component updateComponent(Component transientComponent) {
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
        pm.currentTransaction().commit();
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Component result = pm.getObjectById(Component.class, component.getId());
        SingleThreadedEventService.getInstance().publish(new IndexUpdateEvent(pm.detachCopy(result)));
        return result;
    }

    /**
     * Deletes a Component and all objects dependant on the component.
     * @param component the Component to delete
     */
    public void recursivelyDeleteComponent(Component component) {
        if (component.getChildren() != null) {
            for (Component child: component.getChildren()) {
                recursivelyDeleteComponent(child);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Component result = pm.getObjectById(Component.class, component.getId());
        SingleThreadedEventService.getInstance().publish(new IndexDeleteEvent(pm.detachCopy(result)));

        //todo delete dependencies
        delete(component.getChildren());
        delete(component);
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
        evidence.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(evidence);
        pm.currentTransaction().commit();
        return pm.getObjectById(Evidence.class, evidence.getId());
    }

    /**
     * Returns a List of all License objects.
     * @return a List of all License objects
     */
    @SuppressWarnings("unchecked")
    public List<License> getLicenses() {
        final Query query = pm.newQuery(License.class);
        query.setOrdering("name asc");
        return (List<License>) execute(query);
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
     * @param transientLicense the License object to create
     * @return a created License object
     */
    public License createLicense(License transientLicense) {
        pm.currentTransaction().begin();
        final License license = new License();
        license.setComment(transientLicense.getComment());
        license.setDeprecatedLicenseId(transientLicense.isDeprecatedLicenseId());
        license.setHeader(transientLicense.getHeader());
        license.setOsiApproved(transientLicense.isOsiApproved());
        license.setLicenseId(transientLicense.getLicenseId());
        license.setName(transientLicense.getName());
        license.setTemplate(transientLicense.getTemplate());
        license.setText(transientLicense.getText());
        license.setSeeAlso(transientLicense.getSeeAlso());
        license.setUuid(UUID.randomUUID().toString());
        pm.makePersistent(license);
        pm.currentTransaction().commit();
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final License result = pm.getObjectById(License.class, license.getId());
        SingleThreadedEventService.getInstance().publish(new IndexAddEvent(pm.detachCopy(result)));
        return result;
    }

    /**
     * Creates a new Vulnerability.
     * @param vulnId the name of the vulnerability. This is typically CVE-something
     * @param desc the description of the vulnerability
     * @param source the source of the vulnerability data
     * @param cwe the common weakness enumeration, or weakness categorization
     * @param cvssv2BaseScore the cvss score 0.0 - 10.0
     * @param cvssv2ImpactSubScore the cvss score 0.0 - 10.0
     * @param cvssv2ExploitSubScore the cvss score 0.0 - 10.0
     * @param cvssv2Vector the cvss vector
     * @param cvssv3BaseScore the cvss score 0.0 - 10.0
     * @param cvssv3ImpactSubScore the cvss score 0.0 - 10.0
     * @param cvssv3ExploitSubScore the cvss score 0.0 - 10.0
     * @param cvssv3Vector the cvss vector
     * @param matchedCpe the matched CPE
     * @param matchAlPreviousCpe refer to DC report
     * @return a new Vulnerability object
     */
    public Vulnerability createVulnerability(String vulnId, String desc, Vulnerability.Source source, Cwe cwe,
                                             BigDecimal cvssv2BaseScore, BigDecimal cvssv2ImpactSubScore,
                                             BigDecimal cvssv2ExploitSubScore, String cvssv2Vector,
                                             BigDecimal cvssv3BaseScore, BigDecimal cvssv3ImpactSubScore, BigDecimal cvssv3ExploitSubScore,
                                             String cvssv3Vector, String matchedCpe, String matchAlPreviousCpe) {
        pm.currentTransaction().begin();
        final Vulnerability vuln = new Vulnerability();
        vuln.setVulnId(vulnId);
        vuln.setDescription(desc);
        vuln.setSource(source);
        vuln.setCwe(cwe);
        vuln.setCvssV2BaseScore(cvssv2BaseScore);
        vuln.setCvssV2ImpactSubScore(cvssv2ImpactSubScore);
        vuln.setCvssV2ExploitabilitySubScore(cvssv2ExploitSubScore);
        vuln.setCvssV2Vector(cvssv2Vector);
        vuln.setCvssV3BaseScore(cvssv3BaseScore);
        vuln.setCvssV3ImpactSubScore(cvssv3ImpactSubScore);
        vuln.setCvssV3ExploitabilitySubScore(cvssv3ExploitSubScore);
        vuln.setCvssV3Vector(cvssv3Vector);
        vuln.setMatchedCPE(matchedCpe);
        vuln.setMatchedAllPreviousCPE(matchAlPreviousCpe);
        vuln.setUuid(UUID.randomUUID().toString());
        pm.makePersistent(vuln);
        pm.currentTransaction().commit();
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Vulnerability result = pm.getObjectById(Vulnerability.class, vuln.getId());
        SingleThreadedEventService.getInstance().publish(new IndexAddEvent(pm.detachCopy(result)));
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
     * Returns a vulnerability by it's name (i.e. CVE-2017-0001) and source
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
        pm.currentTransaction().begin();
        pm.makePersistent(cwe);
        pm.currentTransaction().commit();
        return pm.getObjectById(Cwe.class, cwe.getId());
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
    public List<Cwe> getCwes() {
        final Query query = pm.newQuery(Cwe.class);
        query.setOrdering("id asc");
        return (List<Cwe>) execute(query);
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
        pm.currentTransaction().begin();
        pm.makePersistent(dependency);
        pm.currentTransaction().commit();
        return pm.getObjectById(Dependency.class, dependency.getId());
    }

    /**
     * Returns a List of Dependency for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public List<Dependency> getDependencies(Project project) {
        final Query query = pm.newQuery(Dependency.class, "project == :project");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.COMPONENT_ONLY.name());
        return (List<Dependency>) execute(query, project);
    }

    /**
     * Returns a List of Dependency for the specified Component.
     * @param component the Component to retrieve dependencies of
     * @return a List of Dependency objects
     */
    @SuppressWarnings("unchecked")
    public List<Dependency> getDependencies(Component component) {
        final Query query = pm.newQuery(Dependency.class, "component == :component");
        query.getFetchPlan().addGroup(Dependency.FetchGroup.PROJECT_ONLY.name());
        return (List<Dependency>) execute(query, component);
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
    public List<Vulnerability> getVulnerabilities() {
        final Query query = pm.newQuery(Vulnerability.class);
        return (List<Vulnerability>) execute(query);
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
    public List<Vulnerability> getVulnerabilities(Component component) {
        final Query query = pm.newQuery(Vulnerability.class, "components.contains(:component)");
        return (List<Vulnerability>) execute(query, component);
    }

    /**
     * Returns the number of Vulnerability objects for the specified Project.
     * @param project the Project to retrieve vulnerabilities of
     * @return the total number of vulnerabilities for the project
     */
    @SuppressWarnings("unchecked")
    public long getVulnerabilityCount(Project project) {
        long total = 0;
        final List<Dependency> dependencies = getDependencies(project);
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
        final List<Dependency> dependencies = getDependencies(project);
        for (Dependency dependency: dependencies) {
            vulnerabilities.addAll(getVulnerabilities(dependency.getComponent()));
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
            for (Dependency dependency: getDependencies(component)) {
                projects.add(dependency.getProject());
            }
        }
        return projects;
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

}
