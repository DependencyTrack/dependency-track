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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.License;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.util.PurlUtil;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class ComponentQueryManangerPostgresTest extends PersistenceCapableTest {

    @Test
    public void testGetAllComponents() throws Exception {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, false, false);
        assertThat(components.getTotal()).isEqualTo(1000);
    }

    @Test
    public void testGetOutdatedComponents() throws Exception {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, true, false);
        assertThat(components.getTotal()).isEqualTo(200);
    }

    @Test
    public void testGetDirectComponents() throws Exception {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, false, true);
        assertThat(components.getTotal()).isEqualTo(100);
    }

    @Test
    public void getUngroupedOutdatedComponentsTest() throws Exception {

        final Project project = prepareProjectUngroupedComponents();
        var components = qm.getComponents(project, false, true, false);
        assertThat(components.getTotal()).isEqualTo(7);
    }

    @Test
    public void testGetOutdatedDirectComponents() throws Exception {

        final Project project = prepareProject();
        var components = qm.getComponents(project, true, true, true);
        assertThat(components.getTotal()).isEqualTo(75);
    }

    @Test
    public void getUngroupedOutdatedDirectComponentsTest() throws Exception {
        final Project project = prepareProjectUngroupedComponents();
        var components = qm.getComponents(project, true, true, true);
        assertThat(components.getTotal()).isEqualTo(4);
    }

    private Project prepareProject() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final List<String> directDepencencies = new ArrayList<>();
        final List<PackageMetadata> metadataList = new ArrayList<>();
        final List<PackageArtifactMetadata> artifactMetadataList = new ArrayList<>();
        // Generate 1000 dependencies
        for (int i = 0; i < 1000; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setGroup("component-group");
            component.setName("component-name-" + i);
            component.setVersion(i + ".0");
            if (i == 0) {
                var er = new ExternalReference();
                er.setUrl("https://github.com/thinkcmf/thinkcmf/issues/736");
                component.setExternalReferences(List.of(er));
            }
            component.setPurl(new PackageURL(RepositoryType.MAVEN.toString(), "component-group", "component-name-" + i, String.valueOf(i) + ".0", null, null));
            component = qm.createComponent(component, false);
            // direct depencencies
            if (i < 100) {
                // 100 direct depencencies, 900 transitive depencencies
                directDepencencies.add("{\"uuid\":\"" + component.getUuid() + "\"}");
            }
            // Recent & Outdated
            if ((i >= 25) && (i < 225)) {
                // 100 outdated components, 75 of these are direct dependencies, 25 transitive
                metadataList.add(new PackageMetadata(
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        String.valueOf(i + 1) + ".0",
                        null,
                        Instant.now(),
                        null,
                        null));
                artifactMetadataList.add(new PackageArtifactMetadata(
                        component.getPurl(),
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        null, null, null, null, null, null, null, Instant.now()));
            } else if (i < 500) {
                // 300 recent components, 25 of these are direct dependencies
                metadataList.add(new PackageMetadata(
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        String.valueOf(i) + ".0",
                        null,
                        Instant.now(),
                        null,
                        null));
                artifactMetadataList.add(new PackageArtifactMetadata(
                        component.getPurl(),
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        null, null, null, null, null, null, null, Instant.now()));
            } else {
                // 500 components with no metadata, all transitive dependencies
            }
        }
        useJdbiHandle(handle -> {
            new PackageMetadataDao(handle).upsertAll(metadataList);
            new PackageArtifactMetadataDao(handle).upsertAll(artifactMetadataList);
        });
        project.setDirectDependencies("[" + String.join(",", directDepencencies.toArray(new String[0])) + "]");
        return project;
    }

    /**
     * (Regression-)Test for ensuring that all data is mapped in the project component
     */
    @Test
    public void testMappingComponentProjectionWithAllFields() throws Exception {
        final var project = new Project();
        project.setUuid(UUID.fromString("d7173786-60aa-4a4f-a950-c92fe6422307"));
        project.setGroup("projectGroup");
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setClassifier(Classifier.APPLICATION);
        project.setInactiveSince(null);
        project.setCpe("projectCpe");
        project.setPurl("projectPurl");
        project.setSwidTagId("projectSwidTagId");
        List<OrganizationalContact> authors = new ArrayList<>();
        authors.add(new OrganizationalContact() {{
            setName("projectAuthor");
        }});
        project.setAuthors(authors);
        project.setDescription("projectDescription");
        project.setDirectDependencies("[{\"uuid\":\"7e5f6465-d2f2-424f-b1a4-68d186fa2b46\"}]");
        project.setExternalReferences(List.of(new ExternalReference()));
        project.setLastBomImport(new java.util.Date());
        project.setLastBomImportFormat("projectBomFormat");
        project.setLastInheritedRiskScore(7.7);
        project.setPublisher("projectPublisher");
        qm.persist(project);

        final var license = new License();
        license.setUuid(UUID.fromString("dc9876c2-0adc-422b-9f71-3ca78285f138"));
        license.setLicenseId("resolvedLicenseId");
        license.setName("resolvedLicenseName");
        license.setOsiApproved(true);
        license.setFsfLibre(true);
        license.setCustomLicense(true);
        qm.persist(license);

        final var component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("7e5f6465-d2f2-424f-b1a4-68d186fa2b46"));
        component.setGroup("componentGroup");
        component.setName("componentName");
        List<OrganizationalContact> componentAuthors = new ArrayList<>();
        componentAuthors.add(new OrganizationalContact() {{
            setName("componentAuthor");
        }});
        component.setAuthors(componentAuthors);
        component.setVersion("1.0");
        component.setDescription("componentDescription");
        component.setClassifier(Classifier.LIBRARY);
        component.setCopyright("componentCopyright");
        component.setCpe("componentCpe");
        component.setPurl("pkg:maven/a/b@1.0");
        component.setPublisher("componentPublisher");
        component.setPurlCoordinates("componentPurlCoordinates");
        component.setDirectDependencies("[]");
        component.setExtension("componentExtension");
        component.setExternalReferences(List.of(new ExternalReference()));
        component.setFilename("componentFilename");
        component.setLastInheritedRiskScore(5.5);
        component.setSwidTagId("componentSwidTagId");
        component.setInternal(true);
        component.setNotes("componentText");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha384("componentSha384");
        component.setSha512("componentSha512");
        component.setSha3_256("componentSha3_256");
        component.setSha3_384("componentSha3_384");
        component.setSha3_512("componentSha3_512");
        component.setBlake2b_256("componentBlake2b_256");
        component.setBlake2b_384("componentBlake2b_384");
        component.setBlake2b_512("componentBlake2b_512");
        component.setBlake3("componentBlake3");
        component.setLicense("componentLicenseName");
        component.setLicenseExpression("componentLicenseExpression");
        component.setLicenseUrl("componentLicenseUrl");
        component.setResolvedLicense(license);
        qm.persist(component);

        useJdbiHandle(handle -> {
            new PackageMetadataDao(handle).upsertAll(List.of(
                    new PackageMetadata(
                            new PackageURL("pkg:maven/a/b"),
                            "2.0",
                            Instant.ofEpochMilli(220),
                            Instant.ofEpochMilli(222),
                            null,
                            null)));

            new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                    new PackageArtifactMetadata(
                            new PackageURL("pkg:maven/a/b@1.0"),
                            new PackageURL("pkg:maven/a/b"),
                            null, null, null, null,
                            Instant.ofEpochMilli(222),
                            null, null,
                            Instant.now())));
        });

        var components = qm.getComponents(project, false, true, false);
        assertThat(components.getTotal()).isEqualTo(1);
    }

    /**
     * Generate a project with ungrouped dependencies
     * @return A project with 10 dependencies: <ul>
     * <li>7 outdated dependencies</li>
     * <li>3 recent dependencies</li></ul>
     * @throws MalformedPackageURLException
     */
    private Project prepareProjectUngroupedComponents() throws Exception {
        final Project project = qm.createProject("Ungrouped Application", null, null, null, null, null, null, false);
        final List<String> directDepencencies = new ArrayList<>();
        final List<PackageMetadata> metadataList = new ArrayList<>();
        final List<PackageArtifactMetadata> artifactMetadataList = new ArrayList<>();
        // Generate 10 dependencies
        for (int i = 0; i < 10; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("component-name-"+i);
            component.setVersion(String.valueOf(i)+".0");
            component.setPurl(new PackageURL(RepositoryType.PYPI.toString(), null, "component-name-"+i , String.valueOf(i)+".0", null, null));
            component = qm.createComponent(component, false);
            // direct depencencies
            if (i < 4) {
                // 4 direct depencencies, 6 transitive depencencies
                directDepencencies.add("{\"uuid\":\"" + component.getUuid() + "\"}");
            }
            // Recent & Outdated
            if ((i < 7)) {
                metadataList.add(new PackageMetadata(
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        String.valueOf(i+1)+".0",
                        null,
                        Instant.now(),
                        null,
                        null));
            } else {
                metadataList.add(new PackageMetadata(
                        PurlUtil.silentPurlPackageOnly(component.getPurl()),
                        String.valueOf(i)+".0",
                        null,
                        Instant.now(),
                        null,
                        null));
            }
            artifactMetadataList.add(new PackageArtifactMetadata(
                    component.getPurl(),
                    PurlUtil.silentPurlPackageOnly(component.getPurl()),
                    null, null, null, null, null, null, null, Instant.now()));
        }
        useJdbiHandle(handle -> {
            new PackageMetadataDao(handle).upsertAll(metadataList);
            new PackageArtifactMetadataDao(handle).upsertAll(artifactMetadataList);
        });
        project.setDirectDependencies("[" + String.join(",", directDepencencies.toArray(new String[0])) + "]");
        return project;
    }
}
