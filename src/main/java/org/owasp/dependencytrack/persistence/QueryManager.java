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
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Evidence;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectProperty;
import org.owasp.dependencytrack.model.ProjectVersion;
import org.owasp.dependencytrack.model.ProjectVersionProperty;
import org.owasp.dependencytrack.model.Scan;
import javax.jdo.Query;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class QueryManager extends AlpineQueryManager {

    private static final boolean ENFORCE_AUTHORIZATION = Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHORIZATION);

    @SuppressWarnings("unchecked")
    public List<Project> getProjects() {
        Query query = pm.newQuery(Project.class);
        query.setOrdering("name asc");
        return (List<Project>)query.execute();
    }

    public Project createProject(String name) {
        Project project = new Project();
        project.setName(name);
        project.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(project);
        pm.currentTransaction().commit();
        return pm.getObjectById(Project.class, project.getId());
    }

    public Project updateProject(Project transientProject) {
        Project project = getObjectByUuid(Project.class, transientProject.getUuid());
        pm.currentTransaction().begin();
        project.setName(transientProject.getName());
        pm.currentTransaction().commit();
        return pm.getObjectById(Project.class, project.getId());
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

    public ProjectVersion createProjectVersion(Project project, String version) {
        ProjectVersion projectVersion = new ProjectVersion();
        projectVersion.setProject(project);
        projectVersion.setVersion(version);
        projectVersion.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(projectVersion);
        pm.currentTransaction().commit();
        return pm.getObjectById(ProjectVersion.class, projectVersion.getId());
    }

    public ProjectVersion updateProjectVersion(ProjectVersion transientVersion) {
        ProjectVersion version = getObjectByUuid(ProjectVersion.class, transientVersion.getUuid());
        pm.currentTransaction().begin();
        version.setVersion(transientVersion.getVersion());
        pm.currentTransaction().commit();
        return pm.getObjectById(ProjectVersion.class, version.getId());
    }

    public ProjectVersionProperty createProjectVersionProperty(ProjectVersion projectVersion, String key, String value) {
        ProjectVersionProperty property = new ProjectVersionProperty();
        property.setProjectVersion(projectVersion);
        property.setKey(key);
        property.setValue(value);
        pm.currentTransaction().begin();
        pm.makePersistent(property);
        pm.currentTransaction().commit();
        return pm.getObjectById(ProjectVersionProperty.class, property.getId());
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
        return (List<License>)query.execute();
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

    public void bind(Scan scan, Component component) {
        pm.currentTransaction().begin();
        scan.getComponents().add(component);
        component.getScans().add(scan);
        pm.currentTransaction().commit();
    }
}
