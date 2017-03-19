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
import alpine.persistence.AlpineQueryManager;
import alpine.resources.AlpineRequest;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.model.Evidence;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectProperty;
import org.owasp.dependencytrack.model.Scan;
import org.owasp.dependencytrack.model.Vulnerability;
import javax.jdo.Query;
import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class QueryManager extends AlpineQueryManager {

    private static final boolean ENFORCE_AUTHORIZATION = Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHORIZATION);

    /**
     * Default constructor
     */
    public QueryManager() { }

    /**
     * Constructs a new QueryManager
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
    }

    @SuppressWarnings("unchecked")
    public List<Project> getProjects() {
        Query query = pm.newQuery(Project.class);
        query.setOrdering("name asc");
        return (List<Project>)execute(query);
    }

    public Project createProject(String name, String description, String version, Project parent) {
        Project project = new Project();
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setUuid(UUID.randomUUID().toString());
        if (parent != null) {
            project.setParent(parent);
        }
        pm.currentTransaction().begin();
        pm.makePersistent(project);
        pm.currentTransaction().commit();
        return pm.getObjectById(Project.class, project.getId());
    }

    public Project updateProject(Project transientProject) {
        Project project = getObjectByUuid(Project.class, transientProject.getUuid());
        pm.currentTransaction().begin();
        project.setName(transientProject.getName());
        project.setVersion(transientProject.getVersion());
        pm.currentTransaction().commit();
        return pm.getObjectById(Project.class, project.getId());
    }

    public void recursivelyDeleteProject(Project project) {
        if (project.getChildren() != null) {
            for (Project child: project.getChildren()) {
                recursivelyDeleteProject(child);
            }
        }
        delete(project.getProperties());
        delete(getScans(project));
        delete(project.getChildren());
        delete(project);
    }

    public ProjectProperty createProjectProperty(Project project, String key, String value) {
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setKey(key);
        property.setValue(value);
        pm.currentTransaction().begin();
        pm.makePersistent(property);
        pm.currentTransaction().commit();
        return pm.getObjectById(ProjectProperty.class, property.getId());
    }

    public Scan createScan(Project project, Date executed, Date imported) {
        Scan scan = new Scan();
        scan.setExecuted(executed);
        scan.setImported(imported);
        scan.setProject(project);
        scan.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(scan);
        pm.currentTransaction().commit();
        return pm.getObjectById(Scan.class, scan.getId());
    }

    @SuppressWarnings("unchecked")
    public List<Scan> getScans(Project project) {
        Query query = pm.newQuery(Scan.class, "project == :project");
        return (List<Scan>)query.execute(project);
    }

    @SuppressWarnings("unchecked")
    public List<Component> getComponents() {
        Query query = pm.newQuery(Component.class);
        query.setOrdering("name asc");
        return (List<Component>)execute(query);
    }

    @SuppressWarnings("unchecked")
    public Component getComponentByHash(String hash) {
        Query query = pm.newQuery(Component.class, "md5 == :hash || sha1 == :hash");
        List<Component> result = (List<Component>)query.execute(hash);
        return result.size() == 0 ? null : result.get(0);
    }

    public Component createComponent(String name, String filename, String md5, String sha1,
                                     String description, String license, Component parent) {
        Component component = new Component();
        component.setName(name);
        component.setFilename(filename);
        component.setMd5(md5);
        component.setSha1(sha1);
        component.setDescription(description);
        component.setLicense(license);
        component.setParent(parent);
        component.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(component);
        pm.currentTransaction().commit();
        return pm.getObjectById(Component.class, component.getId());
    }

    public Evidence createEvidence(Component component, String type, int confidenceScore,
                                    String source, String name, String value) {
        Evidence evidence = new Evidence();
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

    @SuppressWarnings("unchecked")
    public List<License> getLicenses() {
        Query query = pm.newQuery(License.class);
        query.setOrdering("name asc");
        return (List<License>)execute(query);
    }

    @SuppressWarnings("unchecked")
    public License getLicense(String licenseId) {
        Query query = pm.newQuery(License.class, "licenseId == :licenseId");
        List<License> result = (List<License>)query.execute(licenseId);
        return result.size() == 0 ? null : result.get(0);
    }

    public License createLicense(License transientLicense) {
        pm.currentTransaction().begin();
        License license = new License();
        license.setComment(transientLicense.getComment());
        license.setDeprecatedLicenseId(transientLicense.isDeprecatedLicenseId());
        license.setHeader(transientLicense.getHeader());
        license.setOsiApproved(transientLicense.isOsiApproved());
        license.setLicenseId(transientLicense.getLicenseId());
        license.setName(transientLicense.getName());
        license.setTemplate(transientLicense.getTemplate());
        license.setText(transientLicense.getText());
        pm.makePersistent(license);
        pm.currentTransaction().commit();
        return pm.getObjectById(License.class, license.getId());
    }

    public Vulnerability createVulnerability(String name, String desc, Cwe cwe,
                                             BigDecimal cvss, String matchedCpe, String matchAlPreviousCpe) {
        pm.currentTransaction().begin();
        Vulnerability vuln = new Vulnerability();
        vuln.setName(name);
        vuln.setDescription(desc);
        vuln.setCwe(cwe);
        vuln.setCvssScore(cvss);
        vuln.setMatchedCPE(matchedCpe);
        vuln.setMatchedAllPreviousCPE(matchAlPreviousCpe);
        vuln.setUuid(UUID.randomUUID().toString());
        pm.makePersistent(vuln);
        pm.currentTransaction().commit();
        return pm.getObjectById(Vulnerability.class, vuln.getId());
    }

    @SuppressWarnings("unchecked")
    public Vulnerability getVulnerabilityByName(String name) {
        Query query = pm.newQuery(Vulnerability.class, "name == :name");
        List<Vulnerability> result = (List<Vulnerability>)query.execute(name);
        return result.size() == 0 ? null : result.get(0);
    }

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

    @SuppressWarnings("unchecked")
    public Cwe getCweById(int cweId) {
        Query query = pm.newQuery(Cwe.class, "cweId == :cweId");
        List<Cwe> result = (List<Cwe>)query.execute(cweId);
        return result.size() == 0 ? null : result.get(0);
    }

    @SuppressWarnings("unchecked")
    public List<Cwe> getCwes() {
        Query query = pm.newQuery(Cwe.class);
        query.setOrdering("id asc");
        return (List<Cwe>)execute(query);
    }

    public void bind(Scan scan, Component component) {
        pm.currentTransaction().begin();
        scan.getComponents().add(component);
        component.getScans().add(scan);
        pm.currentTransaction().commit();
    }

    public void bind(Component component, Vulnerability vulnerability) {
        pm.currentTransaction().begin();
        vulnerability.getComponents().add(component);
        component.getVulnerabilities().add(vulnerability);
        pm.currentTransaction().commit();
    }

}
