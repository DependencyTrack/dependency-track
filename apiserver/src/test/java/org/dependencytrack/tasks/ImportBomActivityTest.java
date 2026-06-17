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
package org.dependencytrack.tasks;

import alpine.model.IConfigProperty.PropertyType;
import com.github.packageurl.PackageURL;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.License;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.JDOObjectNotFoundException;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.mockito.Mockito.mock;

class ImportBomActivityTest extends PersistenceCapableTest {

    private DexEngine dexEngineMock;
    private FileStorage fileStorage;
    private ImportBomActivity activity;

    @BeforeEach
    void beforeEach() {
        dexEngineMock = mock(DexEngine.class);
        fileStorage = new MemoryFileStorage();

        activity = new ImportBomActivity(fileStorage, dexEngineMock, false);

        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(
                ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(),
                "true",
                ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ACCEPT_ARTIFACT_CYCLONEDX.getDescription());

        // Required for notifications to be emitted.
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
    }

    private ImportBomArg buildArg(Project project, FileMetadata bomFileMetadata, UUID bomUploadToken) {
        return ImportBomArg.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .setProjectName(project.getName())
                .setProjectVersion(project.getVersion() != null ? project.getVersion() : "")
                .setBomUploadToken(bomUploadToken.toString())
                .setBomFileMetadata(bomFileMetadata)
                .build();
    }

    @Test
    void informTest() throws Exception {
        // Required for license resolution.
        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultLicenses);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-1.xml");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getCpe()).isEqualTo("cpe:2.3:a:acme:example:1.0.0:*:*:*:*:*:*:*");
        assertThat(project.getPurl()).asString().isEqualTo("pkg:maven/com.acme/example@1.0.0");
        assertThat(project.getSwidTagId()).isEqualTo("swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1");
        assertThat(project.getLastBomImport()).isNotNull();
        assertThat(project.getLastBomImportFormat()).isEqualTo("CycloneDX 1.5");
        assertThat(project.getExternalReferences()).isNotNull();
        assertThat(project.getExternalReferences()).hasSize(4);
        assertThat(project.getSupplier()).satisfies(supplier -> {
            assertThat(supplier.getName()).isEqualTo("Foo Incorporated");
            assertThat(supplier.getUrls()).containsOnly("https://foo.bar.com");
            assertThat(supplier.getContacts()).satisfiesExactly(contact -> {
                assertThat(contact.getName()).isEqualTo("Foo Jr.");
                assertThat(contact.getEmail()).isEqualTo("foojr@bar.com");
                assertThat(contact.getPhone()).isEqualTo("123-456-7890");
            });
        });
        assertThat(project.getManufacturer()).satisfies(manufacturer -> {
            assertThat(manufacturer.getName()).isEqualTo("Foo Incorporated");
            assertThat(manufacturer.getUrls()).containsOnly("https://foo.bar.com");
            assertThat(manufacturer.getContacts()).satisfiesExactly(contact -> {
                assertThat(contact.getName()).isEqualTo("Foo Sr.");
                assertThat(contact.getEmail()).isEqualTo("foo@bar.com");
                assertThat(contact.getPhone()).isEqualTo("800-123-4567");
            });
        });

        assertThat(project.getMetadata()).isNotNull();
        assertThat(project.getMetadata().getAuthors()).satisfiesExactly(contact -> {
            assertThat(contact.getName()).isEqualTo("Author");
            assertThat(contact.getEmail()).isEqualTo("author@example.com");
            assertThat(contact.getPhone()).isEqualTo("123-456-7890");
        });
        assertThat(project.getMetadata().getSupplier()).satisfies(manufacturer -> {
            assertThat(manufacturer.getName()).isEqualTo("Foo Incorporated");
            assertThat(manufacturer.getUrls()).containsOnly("https://foo.bar.com");
            assertThat(manufacturer.getContacts()).satisfiesExactly(contact -> {
                assertThat(contact.getName()).isEqualTo("Foo Jr.");
                assertThat(contact.getEmail()).isEqualTo("foojr@bar.com");
                assertThat(contact.getPhone()).isEqualTo("123-456-7890");
            });
        });

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(1);

        final Component component = components.get(0);
        assertThat(component.getAuthors().get(0).getName()).isEqualTo("Sometimes this field is long because it is composed of a list of authors......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................");
        assertThat(component.getPublisher()).isEqualTo("Example Incorporated");
        assertThat(component.getSupplier().getName()).isEqualTo("Foo Incorporated");
        assertThat(component.getGroup()).isEqualTo("com.example");
        assertThat(component.getName()).isEqualTo("xmlutil");
        assertThat(component.getVersion()).isEqualTo("1.0.0");
        assertThat(component.getDescription()).isEqualTo("A makebelieve XML utility library");
        assertThat(component.getCpe()).isEqualTo("cpe:/a:example:xmlutil:1.0.0");
        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:maven/com.example/xmlutil@1.0.0?download_url=https%3A%2F%2Fon-premises.url%2Frepository%2Fnpm%2F%40babel%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration-7.18.6.tgz");
        assertThat(component.getResolvedLicense()).isNotNull();
        assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("Apache-2.0");
        assertThat(component.getLicense()).isNull();
        assertThat(component.getLicenseUrl()).isEqualTo("https://www.apache.org/licenses/LICENSE-2.0.txt");

        assertThat(component.getProperties()).satisfiesExactlyInAnyOrder(
                property -> {
                    assertThat(property.getGroupName()).isEqualTo("foo");
                    assertThat(property.getPropertyName()).isEqualTo("bar");
                    assertThat(property.getPropertyValue()).isEqualTo("baz");
                    assertThat(property.getPropertyType()).isEqualTo(PropertyType.STRING);
                    assertThat(property.getDescription()).isNull();
                },
                property -> {
                    assertThat(property.getGroupName()).isNull();
                    assertThat(property.getPropertyName()).isEqualTo("foo");
                    assertThat(property.getPropertyValue()).isEqualTo("bar");
                    assertThat(property.getPropertyType()).isEqualTo(PropertyType.STRING);
                    assertThat(property.getDescription()).isNull();
                },
                property -> {
                    assertThat(property.getGroupName()).isEqualTo("foo");
                    assertThat(property.getPropertyName()).isEqualTo("bar");
                    assertThat(property.getPropertyValue()).isEqualTo("qux");
                    assertThat(property.getPropertyType()).isEqualTo(PropertyType.STRING);
                    assertThat(property.getDescription()).isNull();
                },
                property -> {
                    assertThat(property.getGroupName()).isNull();
                    assertThat(property.getPropertyName()).isEqualTo("long");
                    assertThat(property.getPropertyValue()).isEqualTo("a".repeat(1021) + "...");
                    assertThat(property.getPropertyType()).isEqualTo(PropertyType.STRING);
                    assertThat(property.getDescription()).isNull();
                }
        );
    }

    @Test
    void informTestWithComponentAlreadyExistsForIntegrityCheck() throws Exception {
        // Required for license resolution.
        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultLicenses);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-1.xml");
        final var bomUploadToken = UUID.randomUUID();
        useJdbiTransaction(handle -> {
            new PackageMetadataDao(handle).upsertAll(List.of(
                    new PackageMetadata(
                            new PackageURL("pkg:maven/com.example/xmlutil"),
                            "1.0.0",
                            null,
                            Instant.now(),
                            null,
                            null)));
            new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                    new PackageArtifactMetadata(
                            new PackageURL("pkg:maven/com.example/xmlutil@1.0.0?download_url=https%3A%2F%2Fon-premises.url%2Frepository%2Fnpm%2F%40babel%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration-7.18.6.tgz"),
                            new PackageURL("pkg:maven/com.example/xmlutil"),
                            null, null, null, null, null,
                            null, null,
                            Instant.now().minus(2, ChronoUnit.HOURS))));

        });
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getLastBomImport()).isNotNull();
        assertThat(project.getLastBomImportFormat()).isEqualTo("CycloneDX 1.5");
        assertThat(project.getExternalReferences()).isNotNull();
        assertThat(project.getExternalReferences()).hasSize(4);

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(1);

        final Component component = components.get(0);
        assertThat(component.getAuthors().get(0).getName()).isEqualTo("Sometimes this field is long because it is composed of a list of authors......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................");
        assertThat(component.getPublisher()).isEqualTo("Example Incorporated");
        assertThat(component.getGroup()).isEqualTo("com.example");
        assertThat(component.getName()).isEqualTo("xmlutil");
        assertThat(component.getVersion()).isEqualTo("1.0.0");
        assertThat(component.getDescription()).isEqualTo("A makebelieve XML utility library");
        assertThat(component.getCpe()).isEqualTo("cpe:/a:example:xmlutil:1.0.0");
        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:maven/com.example/xmlutil@1.0.0?download_url=https%3A%2F%2Fon-premises.url%2Frepository%2Fnpm%2F%40babel%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration-7.18.6.tgz");
        assertThat(component.getResolvedLicense()).isNotNull();
        assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("Apache-2.0");
        assertThat(component.getLicense()).isNull();
        assertThat(component.getLicenseUrl()).isEqualTo("https://www.apache.org/licenses/LICENSE-2.0.txt");
    }

    @Test
    void informWithEmptyBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-empty.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNotNull();

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();
    }

    @Test
    void informWithInvalidBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomFileMetadata = storeBomFile("bom-invalid.json");
        final var bomUploadToken = UUID.randomUUID();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken)));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
            assertThat(notification.getTitle()).isNotEmpty();
            assertThat(notification.getContent()).isNotEmpty();
            assertThat(notification.hasSubject()).isTrue();
            assertThat(notification.getSubject().is(BomProcessingFailedSubject.class)).isTrue();
            final var subject = notification.getSubject().unpack(BomProcessingFailedSubject.class);
            assertThat(subject.hasProject()).isTrue();
            assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
            assertThat(subject.getBom().getContent()).isEqualTo("(Omitted)");
            assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
            assertThat(subject.getBom().getSpecVersion()).isEmpty();
        });

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNull();
        assertThat(project.getExternalReferences()).isNull();
        assertThat(project.getExternalReferences()).isNull();

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();
    }

    @Test
    void testBomProcessingShouldFailIfProjectDoesNotExists() throws Exception {
        //project should not be persisted for this test condition
        Project project = new Project();
        project.setUuid(UUID.randomUUID());
        project.setName("test-project");
        project.setId(1);
        final var bomFileMetadata = storeBomFile("bom-1.xml");
        final var bomUploadToken = UUID.randomUUID();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken)));
    }

    @Test
    void informWithBloatedBomTest() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-bloated.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox())
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED))
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED))
                .noneSatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED));

        final List<Bom> boms = qm.getAllBoms(project);
        assertThat(boms).hasSize(1);
        final Bom bom = boms.get(0);
        assertThat(bom.getBomFormat()).isEqualTo("CycloneDX");
        assertThat(bom.getSpecVersion()).isEqualTo("1.3");
        assertThat(bom.getBomVersion()).isEqualTo(1);
        assertThat(bom.getSerialNumber()).isEqualTo("6d780157-0f8e-4ef1-8e9b-1eb48b2fad6f");

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getGroup()).isNull(); // Not overridden by BOM import
        assertThat(project.getName()).isEqualTo("Acme Example"); // Not overridden by BOM import
        assertThat(project.getVersion()).isEqualTo("1.0"); // Not overridden by BOM import
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getPurl()).isNotNull();
        assertThat(project.getPurl().canonicalize()).isEqualTo("pkg:npm/bloated@1.0.0");
        assertThat(project.getDirectDependencies()).isNotNull();

        // Make sure we ingested all components of the BOM.
        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(9056);

        // Assert some basic properties that should be present on all components.
        for (final Component component : components) {
            assertThat(component.getName()).isNotEmpty();
            assertThat(component.getVersion()).isNotEmpty();
            assertThat(component.getPurl()).isNotNull();
        }

        // Ensure dependency graph has been ingested completely, by asserting on the number leaf nodes of the graph.
        // This number can be verified using this Python script:
        //
        // import json
        // with open("bloated.bom.json", "r") as f:
        //     bom = json.load(f)
        // len(list(filter(lambda x: len(x.get("dependsOn", [])) == 0, bom["dependencies"])))
        final long componentsWithoutDirectDependencies = components.stream()
                .map(Component::getDirectDependencies)
                .filter(Objects::isNull)
                .count();
        assertThat(componentsWithoutDirectDependencies).isEqualTo(6378);

    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2519
    void informIssue2519Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        // Upload the same BOM again a few times.
        // Ensure processing does not fail, and the number of components ingested doesn't change.
        for (int i = 0; i < 3; i++) {
            final var bomFileMetadata = storeBomFile("bom-issue2519.xml");
            final var bomUploadToken = UUID.randomUUID();
            activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
            assertBomProcessedNotification();

            // Ensure the expected amount of components is present.
            assertThat(qm.getAllComponents(project)).hasSize(1756);
        }
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2859
    void informIssue2859Test() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        assertThatNoException().isThrownBy(() -> {
            final var bomFileMetadata = storeBomFile("bom-issue2859.xml");
            final var bomUploadToken = UUID.randomUUID();
            activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        });
    }

    @Test
    void informWithLicenseResolutionByIdOrNameTest() throws Exception {
        final var license = new License();
        license.setLicenseId("MIT");
        license.setName("MIT License");
        qm.persist(license);

        final var project = new Project();
        project.setName("acme-license-app");
        qm.persist(project);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b80",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib-x",
                      "licenses": [
                        {
                          "license": {
                            "name": "MIT"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("MIT");
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/1905
    void informIssue1905Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 3; i++) {
            final var bomFileMetadata = storeBomFile("bom-issue1905.json");
            final var bomUploadToken = UUID.randomUUID();
            activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));

            assertBomProcessedNotification();
            qm.truncateNotificationOutbox();

            // Ensure all expected components are present.
            // In this particular case, both components from the BOM are supposed to NOT be merged.
            assertThat(qm.getAllComponents(project)).satisfiesExactlyInAnyOrder(
                    component -> {
                        assertThat(component.getClassifier()).isEqualTo(Classifier.LIBRARY);
                        assertThat(component.getName()).isEqualTo("cloud.google.com/go/storage");
                        assertThat(component.getVersion()).isEqualTo("v1.13.0");
                        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:golang/cloud.google.com/go/storage@v1.13.0?type=package");
                        assertThat(component.getSha256()).isNull();
                    },
                    component -> {
                        assertThat(component.getClassifier()).isEqualTo(Classifier.LIBRARY);
                        assertThat(component.getName()).isEqualTo("cloud.google.com/go/storage");
                        assertThat(component.getVersion()).isEqualTo("v1.13.0");
                        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:golang/cloud.google.com/go/storage@v1.13.0?goarch=amd64&goos=darwin&type=module");
                        assertThat(component.getSha256()).isEqualTo("6a63ef842388f8796da7aacfbbeeb661dc2122b8dffb7e0f29500be07c206309");
                    }
            );
        }
    }

    @Test
    void informIssue3309Test() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Runnable assertProjectAuthors = () -> {
            qm.getPersistenceManager().evictAll();
            assertThat(project.getMetadata()).isNotNull();
            assertThat(project.getMetadata().getAuthors()).satisfiesExactly(author -> {
                assertThat(author.getName()).isEqualTo("Author Name");
                assertThat(author.getEmail()).isEqualTo("author@example.com");
            });
        };

        var bomFileMetadata = storeBomFile("bom-issue3309.json");
        var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        assertProjectAuthors.run();


        bomFileMetadata = storeBomFile("bom-issue3309.json");
        bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        assertProjectAuthors.run();
    }

    @Test
    void informWithComponentsUnderMetadataBomTest() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-metadata-components.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));

        assertThat(qm.getNotificationOutbox())
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED))
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED))
                .noneSatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED));

        final List<Bom> boms = qm.getAllBoms(project);
        assertThat(boms).hasSize(1);
        final Bom bom = boms.get(0);
        assertThat(bom.getBomFormat()).isEqualTo("CycloneDX");
        assertThat(bom.getSpecVersion()).isEqualTo("1.4");
        assertThat(bom.getBomVersion()).isEqualTo(1);
        assertThat(bom.getSerialNumber()).isEqualTo("d7cf8503-6d80-4219-ab4c-3bab8f250ee7");

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getGroup()).isNull(); // Not overridden by BOM import
        assertThat(project.getName()).isEqualTo("Acme Example"); // Not overridden by BOM import
        assertThat(project.getVersion()).isEqualTo("1.0"); // Not overridden by BOM import
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getPurl()).isNotNull();
        assertThat(project.getPurl().canonicalize()).isEqualTo("pkg:maven/test/Test@latest?type=jar");
        assertThat(project.getDirectDependencies()).isNotNull();

        // Make sure we ingested all components of the BOM.
        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(185);
    }

    @Test
    void informWithDelayedBomProcessedNotification() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-1.xml");
        final var bomUploadToken = UUID.randomUUID();

        final var arg = buildArg(project, bomFileMetadata, bomUploadToken);
        new ImportBomActivity(fileStorage, dexEngineMock, /* delayBomProcessedNotification */ true).execute(null, arg);
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                // BOM_PROCESSED notification should not have been sent.
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED));
    }

    @Test
    void informWithDelayedBomProcessedNotificationAndNoComponents() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-empty.json");
        final var bomUploadToken = UUID.randomUUID();

        final var arg = buildArg(project, bomFileMetadata, bomUploadToken);
        new ImportBomActivity(fileStorage, dexEngineMock, /* delayBomProcessedNotification */ true).execute(null, arg);
        // BOM_PROCESSED notification should not have been sent eagerly.
        // It will be dispatched by DelayedBomProcessedNotificationEmitter
        // when the AnalyzeProjectWorkflow completes.
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED));
    }

    @Test
    void informWithComponentWithoutPurl() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-no-purl.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));
        // No REPO_META_ANALYSIS_COMMAND event because the component doesn't have a PURL.


        assertThat(qm.getAllComponents(project))
                .satisfiesExactly(component -> assertThat(component.getName()).isEqualTo("acme-lib"));
    }

    @Test
    void informWithCustomLicenseResolutionTest() throws Exception {
        final var customLicense = new License();
        customLicense.setName("custom license foobar");
        qm.createCustomLicense(customLicense, false);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-custom-license.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));


        assertThat(qm.getAllComponents(project)).satisfiesExactly(
                component -> {
                    assertThat(component.getName()).isEqualTo("acme-lib-a");
                    assertThat(component.getResolvedLicense()).isNotNull();
                    assertThat(component.getResolvedLicense().getName()).isEqualTo("custom license foobar");
                    assertThat(component.getLicense()).isNull();
                },
                component -> {
                    assertThat(component.getName()).isEqualTo("acme-lib-b");
                    assertThat(component.getResolvedLicense()).isNull();
                    assertThat(component.getLicense()).isEqualTo("does not exist");
                },
                component -> {
                    assertThat(component.getName()).isEqualTo("acme-lib-c");
                    assertThat(component.getResolvedLicense()).isNull();
                    assertThat(component.getLicense()).isNull();
                }
        );
    }

    @Test
    void informWithBomContainingLicenseExpressionTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-license-expression.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));


        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isEqualTo("EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0");
            assertThat(component.getResolvedLicense()).isNull();
        });
    }

    @Test
    void informWithBomContainingLicenseExpressionWithSingleIdTest() throws Exception {
        final var license = new License();
        license.setLicenseId("EPL-2.0");
        license.setName("Eclipse Public License 2.0");
        qm.persist(license);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-license-expression-single-license.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));


        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("EPL-2.0");
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isEqualTo("EPL-2.0");
        });
    }

    @Test
    void informWithBomContainingInvalidLicenseExpressionTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-invalid-license-expression.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));


        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isNull();
            assertThat(component.getResolvedLicense()).isNull();
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3433
    void informIssue3433Test() throws Exception {
        final var license = new License();
        license.setLicenseId("GPL-3.0-or-later");
        license.setName("GPL-3.0-or-later");
        qm.persist(license);

        final var project = new Project();
        project.setName("acme-license-app");
        qm.persist(project);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b80",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib-x",
                      "licenses": [
                        {
                          "license": {
                            "name": "GPL-3.0-or-later"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("GPL-3.0-or-later");
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3498
    void informUpdateExistingLicenseTest() throws Exception {
        final var existingLicense = new License();
        existingLicense.setLicenseId("GPL-3.0-or-later");
        existingLicense.setName("GPL-3.0-or-later");
        qm.persist(existingLicense);

        final var updatedLicense = new License();
        updatedLicense.setLicenseId("Apache-2.0");
        updatedLicense.setName("Apache-2.0");
        qm.persist(updatedLicense);

        final var project = new Project();
        project.setName("acme-update-license-app");
        qm.persist(project);

        final byte[] existingBomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "publisher": "Acme Inc",
                      "group": "com.acme",
                      "name": "acme-lib-y",
                      "version": "2.0.0",
                      "licenses": [
                        {
                          "license": {
                            "name": "GPL-3.0-or-later"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        var bomFileMetadata = storeBomFile(existingBomBytes);
        var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo(existingLicense.getLicenseId());
        });

        // Upload bom again but with new license
        final byte[] updatedBomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "publisher": "Acme Inc",
                      "group": "com.acme",
                      "name": "acme-lib-y",
                      "version": "2.0.0",
                      "licenses": [
                        {
                          "license": {
                            "name": "Apache-2.0"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        bomFileMetadata = storeBomFile(updatedBomBytes);
        bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        qm.getPersistenceManager().evictAll();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo(updatedLicense.getLicenseId());
        });

    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3498
    void informDeleteExistingLicenseTest() throws Exception {
        final var existingLicense = new License();
        existingLicense.setLicenseId("GPL-3.0-or-later");
        existingLicense.setName("GPL-3.0-or-later");
        qm.persist(existingLicense);

        final var project = new Project();
        project.setName("acme-update-license-app");
        qm.persist(project);

        final byte[] existingBomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "publisher": "Acme Inc",
                      "group": "com.acme",
                      "name": "acme-lib-y",
                      "version": "2.0.0",
                      "licenses": [
                        {
                          "license": {
                            "name": "GPL-3.0-or-later"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        var bomFileMetadata = storeBomFile(existingBomBytes);
        var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo(existingLicense.getLicenseId());
        });

        // Upload bom again but with license deleted
        final byte[] updatedBomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "publisher": "Acme Inc",
                      "group": "com.acme",
                      "name": "acme-lib-y",
                      "version": "2.0.0",
                      "licenses": []
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        bomFileMetadata = storeBomFile(updatedBomBytes);
        bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        qm.getPersistenceManager().evictAll();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNull();
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseUrl()).isNull();
            assertThat(component.getLicenseExpression()).isNull();
        });
    }

    @Test
    void informWithBomContainingServiceTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-service.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));


        assertThat(qm.getAllComponents(project)).isNotEmpty();
        assertThat(qm.getAllServiceComponents(project)).isNotEmpty();
    }

    @Test
    void informWithBomContainingMetadataToolsDeprecatedTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-metadata-tool-deprecated.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getMetadata()).isNotNull();
        assertThat(project.getMetadata().getTools()).isNotNull();
        assertThat(project.getMetadata().getTools().components()).satisfiesExactly(component -> {
            assertThat(component.getSupplier()).isNotNull();
            assertThat(component.getSupplier().getName()).isEqualTo("Awesome Vendor");
            assertThat(component.getName()).isEqualTo("Awesome Tool");
            assertThat(component.getVersion()).isEqualTo("9.1.2");
            assertThat(component.getSha1()).isEqualTo("25ed8e31b995bb927966616df2a42b979a2717f0");
            assertThat(component.getSha256()).isEqualTo("a74f733635a19aefb1f73e5947cef59cd7440c6952ef0f03d09d974274cbd6df");
        });
        assertThat(project.getMetadata().getTools().services()).isNull();
    }

    @Test
    void informWithBomContainingMetadataToolsTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var bomFileMetadata = storeBomFile("bom-metadata-tool.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getMetadata()).isNotNull();
        assertThat(project.getMetadata().getTools()).isNotNull();
        assertThat(project.getMetadata().getTools().components()).satisfiesExactly(component -> {
            assertThat(component.getGroup()).isEqualTo("Awesome Vendor");
            assertThat(component.getName()).isEqualTo("Awesome Tool");
            assertThat(component.getVersion()).isEqualTo("9.1.2");
            assertThat(component.getSha1()).isEqualTo("25ed8e31b995bb927966616df2a42b979a2717f0");
            assertThat(component.getSha256()).isEqualTo("a74f733635a19aefb1f73e5947cef59cd7440c6952ef0f03d09d974274cbd6df");
        });
        assertThat(project.getMetadata().getTools().services()).satisfiesExactly(service -> {
            assertThat(service.getProvider()).isNotNull();
            assertThat(service.getProvider().getName()).isEqualTo("Acme Org");
            assertThat(service.getProvider().getUrls()).containsOnly("https://example.com");
            assertThat(service.getGroup()).isEqualTo("com.example");
            assertThat(service.getName()).isEqualTo("Acme Signing Server");
            assertThat(service.getDescription()).isEqualTo("Signs artifacts");
            assertThat(service.getEndpoints()).containsExactlyInAnyOrder(
                    "https://example.com/sign",
                    "https://example.com/verify",
                    "https://example.com/tsa"
            );
        });
    }

    @Test
    void informWithBomContainingTimestampTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomFileMetadata = storeBomFile("bom-metadata-timestamp.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        var boms = qm.getAllBoms(project);
        assertThat(boms.get(0).getGenerated()).isEqualTo("2021-02-09T20:40:32Z");
    }

    @Test
    void informWithExistingComponentPropertiesAndBomWithoutComponentProperties() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        final var componentProperty = new ComponentProperty();
        componentProperty.setComponent(component);
        componentProperty.setPropertyName("foo");
        componentProperty.setPropertyValue("bar");
        componentProperty.setPropertyType(PropertyType.STRING);
        qm.persist(componentProperty);

        final var bomFileMetadata = storeBomFile("""
                {
                  "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getProperties()).isEmpty();
    }

    @Test
    void informWithExistingComponentPropertiesAndBomWithComponentProperties() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        final var componentProperty = new ComponentProperty();
        componentProperty.setComponent(component);
        componentProperty.setPropertyName("foo");
        componentProperty.setPropertyValue("bar");
        componentProperty.setPropertyType(PropertyType.STRING);
        qm.persist(componentProperty);

        final var bomFileMetadata = storeBomFile("bom-component-property.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getProperties()).satisfiesExactly(property -> {
            assertThat(property.getGroupName()).isNull();
            assertThat(property.getPropertyName()).isEqualTo("foo");
            assertThat(property.getPropertyValue()).isEqualTo("baz");
            assertThat(property.getUuid()).isNotEqualTo(componentProperty.getUuid());
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3957
    void informIssue3957Test() throws Exception {
        final var licenseA = new License();
        licenseA.setLicenseId("GPL-1.0");
        licenseA.setName("GNU General Public License v1.0 only");
        qm.persist(licenseA);

        final var licenseB = new License();
        licenseB.setLicenseId("GPL-1.0-only");
        licenseB.setName("GNU General Public License v1.0 only");
        qm.persist(licenseB);

        final var project = new Project();
        project.setName("acme-license-app");
        qm.persist(project);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b80",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib-x",
                      "licenses": [
                        {
                          "license": {
                            "name": "GNU General Public License v1.0 only"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("GPL-1.0");
        });
    }

    @Test
    void informIssue3981Test() throws Exception {
        final var project = new Project();
        project.setName("acme-license-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b80",
                  "version": 1,
                  "metadata": {
                    "authors": [
                      {
                        "name": "foo",
                        "email": "foo@example.com"
                      }
                    ]
                  },
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib-x"
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        var bomFileMetadata = storeBomFile(bomBytes);
        var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        final UUID clonedProjectUuid = inJdbiTransaction(handle -> handle.attach(ProjectDao.class).cloneProject(
                new CloneProjectCommand(project.getUuid(), "3.2.1", true, true, true, true, true, true, true, true, true, true)));

        bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b80",
                  "version": 1,
                  "metadata": {
                    "authors": [
                      {
                        "name": "bar",
                        "email": "bar@example.com"
                      }
                    ]
                  },
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib-x"
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final Project clonedProject = qm.getObjectByUuid(Project.class, clonedProjectUuid);

        bomFileMetadata = storeBomFile(bomBytes);
        bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(clonedProject, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().evictAll();

        assertThat(project.getMetadata().getAuthors()).satisfiesExactly(author -> {
            assertThat(author.getName()).isEqualTo("foo");
            assertThat(author.getEmail()).isEqualTo("foo@example.com");
        });

        assertThat(clonedProject.getMetadata().getAuthors()).satisfiesExactly(author -> {
            assertThat(author.getName()).isEqualTo("bar");
            assertThat(author.getEmail()).isEqualTo("bar@example.com");
        });
    }

    @Test
    void informIssue3936Test() throws Exception {

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.persist(project);
        List<String> boms = new ArrayList<>(Arrays.asList("bom-issue3936-authors.json", "bom-issue3936-author.json", "bom-issue3936-both.json"));
        int i = 0;
        for (String bom : boms) {
            final var bomFileMetadata = storeBomFile(bom);
            final var bomUploadToken = UUID.randomUUID();
            activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
            assertBomProcessedNotification();
            qm.getPersistenceManager().evictAll();
            final List<Component> components = qm.getAllComponents(project);
            assertThat(components).isNotEmpty();
            Component component = components.getFirst();
            assertThat(component.getAuthors().get(0).getName()).isEqualTo("Joane Doe et al.");
            if (i == 2) {
                assertThat(component.getAuthors().size()).isEqualTo(2);
            } else {
                assertThat(component.getAuthors().size()).isEqualTo(1);
                i++;
            }
        }
    }

    @Test
    void informIssue4455Test() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        final var bomFileMetadata = storeBomFile("bom-issue4455.json");
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();
        qm.getPersistenceManager().refresh(project);

        assertThat(project.getDirectDependencies()).satisfies(directDependenciesJson -> {
            final var jsonReader = Json.createReader(
                    new StringReader(directDependenciesJson));
            final var directDependenciesArray = jsonReader.readArray();

            final var uuidsSeen = new HashSet<String>();
            for (int i = 0; i < directDependenciesArray.size(); i++) {
                final var directDependencyObject = directDependenciesArray.getJsonObject(i);
                final String directDependencyUuid = directDependencyObject.getString("uuid");
                if (!uuidsSeen.add(directDependencyUuid)) {
                    fail("Duplicate UUID %s in project's directDependencies: %s".formatted(
                            directDependencyUuid, directDependenciesJson));
                }
            }
        });

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).allSatisfy(component -> {
            if (component.getDirectDependencies() == null) {
                return;
            }

            final JsonReader jsonReader = Json.createReader(
                    new StringReader(component.getDirectDependencies()));
            final JsonArray directDependenciesArray = jsonReader.readArray();

            final var uuidsSeen = new HashSet<String>();
            for (int i = 0; i < directDependenciesArray.size(); i++) {
                final JsonObject directDependencyObject = directDependenciesArray.getJsonObject(i);
                final String directDependencyUuid = directDependencyObject.getString("uuid");
                if (!uuidsSeen.add(directDependencyUuid)) {
                    fail("Duplicate UUID %s in component's directDependencies: %s".formatted(
                            directDependencyUuid, component.getDirectDependencies()));
                }
            }
        });
    }

    @Test
    void informWithDuplicateBomRefsMappedToSameIdentityMergesDirectDependencies() throws Exception {
        final var project = new Project();
        project.setName("acme-duplicate-bom-ref-app");
        qm.persist(project);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "a1",
                      "group": "com.example",
                      "name": "a",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.example/a@1.0.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "a2",
                      "group": "com.example",
                      "name": "a",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.example/a@1.0.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "b1",
                      "group": "com.example",
                      "name": "b",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.example/b@1.0.0"
                    }
                  ],
                  "dependencies": [
                    {
                      "ref": "a1",
                      "dependsOn": ["b1"]
                    },
                    {
                      "ref": "a2",
                      "dependsOn": []
                    },
                    {
                      "ref": "b1",
                      "dependsOn": []
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(2);

        final Component aComponent = components.stream()
                .filter(component -> component.getPurl() != null
                        && "pkg:maven/com.example/a@1.0.0".equals(component.getPurl().canonicalize()))
                .findFirst()
                .orElseThrow();
        final Component bComponent = components.stream()
                .filter(component -> component.getPurl() != null
                        && "pkg:maven/com.example/b@1.0.0".equals(component.getPurl().canonicalize()))
                .findFirst()
                .orElseThrow();

        assertThat(aComponent.getDirectDependencies()).isNotNull();
        final JsonArray directDependencies = Json.createReader(new StringReader(aComponent.getDirectDependencies())).readArray();
        assertThat(directDependencies).hasSize(1);
        assertThat(directDependencies.getJsonObject(0).getString("uuid"))
                .isEqualTo(bComponent.getUuid().toString());
    }

    @Test
    void informWithExistingDuplicateComponentPropertiesAndBomWithDuplicateComponentProperties() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        final var componentPropertyA = new ComponentProperty();
        componentPropertyA.setComponent(component);
        componentPropertyA.setPropertyName("foo");
        componentPropertyA.setPropertyValue("bar");
        componentPropertyA.setPropertyType(PropertyType.STRING);
        qm.persist(componentPropertyA);

        final var componentPropertyB = new ComponentProperty();
        componentPropertyB.setComponent(component);
        componentPropertyB.setPropertyName("foo");
        componentPropertyB.setPropertyValue("bar");
        componentPropertyB.setPropertyType(PropertyType.STRING);
        qm.persist(componentPropertyB);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib",
                      "properties": [
                        {
                          "name": "foo",
                          "value": "bar"
                        },
                        {
                          "name": "foo",
                          "value": "bar"
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().evictAll();
        assertThatNoException()
                .isThrownBy(() -> qm.getPersistenceManager().refresh(componentPropertyA));
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getPersistenceManager().refresh(componentPropertyB));
        assertThat(component.getProperties()).satisfiesExactly(property -> {
            assertThat(property.getGroupName()).isNull();
            assertThat(property.getPropertyName()).isEqualTo("foo");
            assertThat(property.getPropertyValue()).isEqualTo("bar");
            assertThat(property.getUuid()).isEqualTo(componentPropertyA.getUuid());
        });
    }

    @Test
    void informWithEmptyComponentAndServiceNameTest() throws Exception {
        final var project = new Project();
        project.setName("acme-license-app");
        qm.persist(project);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b80",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": ""
                    }
                  ],
                  "services": [
                    {
                      "name": ""
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllComponents(project)).satisfiesExactly(component ->
                assertThat(component.getName()).isEqualTo("-"));
        assertThat(qm.getAllServiceComponents(project)).satisfiesExactly(service ->
                assertThat(service.getName()).isEqualTo("-"));
    }

    @Test
    void informWithComponentOccurrencesTest() throws Exception {
        final var project = new Project();
        project.setName("acme-license-app");
        qm.persist(project);

        final byte[] bomBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib",
                      "evidence": {
                        "occurrences": [
                          {
                            "location": "/foo/bar/baz"
                          },
                          {
                            "location": "/foo/bar.js",
                            "line": 5,
                            "offset": 666,
                            "symbol": "someSymbol"
                          }
                        ]
                      }
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllComponents(project)).satisfiesExactly(component ->
                assertThat(component.getOccurrences()).satisfiesExactlyInAnyOrder(
                        occurrence -> {
                            assertThat(occurrence.getLocation()).isEqualTo("/foo/bar/baz");
                            assertThat(occurrence.getLine()).isNull();
                            assertThat(occurrence.getOffset()).isNull();
                            assertThat(occurrence.getSymbol()).isNull();
                            assertThat(occurrence.getCreatedAt()).isNotNull();
                        },
                        occurrence -> {
                            assertThat(occurrence.getLocation()).isEqualTo("/foo/bar.js");
                            assertThat(occurrence.getLine()).isEqualTo(5);
                            assertThat(occurrence.getOffset()).isEqualTo(666);
                            assertThat(occurrence.getSymbol()).isEqualTo("someSymbol");
                            assertThat(occurrence.getCreatedAt()).isNotNull();
                        }));
    }

    @Test
    void informWithExistingComponentOccurrencesAndBomWithComponentOccurrencesTest() throws Exception {
        final var project = new Project();
        project.setName("acme-license-app");
        qm.persist(project);

        final var existingComponent = new Component();
        existingComponent.setProject(project);
        existingComponent.setName("acme-lib");
        qm.persist(existingComponent);

        final var existingOccurrenceA = new ComponentOccurrence();
        existingOccurrenceA.setComponent(existingComponent);
        existingOccurrenceA.setLocation("/foo/bar/baz");
        qm.persist(existingOccurrenceA);

        final var existingOccurrenceB = new ComponentOccurrence();
        existingOccurrenceB.setComponent(existingComponent);
        existingOccurrenceB.setLocation("/foo/bar.js");
        existingOccurrenceB.setLine(5);
        existingOccurrenceB.setOffset(666);
        existingOccurrenceB.setSymbol("someSymbol");
        qm.persist(existingOccurrenceB);

        final byte[] bomBytes = /* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib",
                      "evidence": {
                        "occurrences": [
                          {
                            "location": "/foo/bar.js",
                            "line": 5,
                            "offset": 666,
                            "symbol": "someSymbol"
                          },
                          {
                            "location": "/foo.js",
                            "line": 666
                          }
                        ]
                      }
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomFileMetadata = storeBomFile(bomBytes);
        final var bomUploadToken = UUID.randomUUID();
        activity.execute(null, buildArg(project, bomFileMetadata, bomUploadToken));
        assertBomProcessedNotification();

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllComponents(project)).satisfiesExactly(component ->
                assertThat(component.getOccurrences()).satisfiesExactlyInAnyOrder(
                        occurrence -> {
                            assertThat(occurrence.getId()).isEqualTo(existingOccurrenceB.getId());
                            assertThat(occurrence.getLocation()).isEqualTo("/foo/bar.js");
                            assertThat(occurrence.getLine()).isEqualTo(5);
                            assertThat(occurrence.getOffset()).isEqualTo(666);
                            assertThat(occurrence.getSymbol()).isEqualTo("someSymbol");
                            assertThat(occurrence.getCreatedAt()).isNotNull();
                        },
                        occurrence -> {
                            assertThat(occurrence.getLocation()).isEqualTo("/foo.js");
                            assertThat(occurrence.getLine()).isEqualTo(666);
                            assertThat(occurrence.getOffset()).isNull();
                            assertThat(occurrence.getSymbol()).isNull();
                            assertThat(occurrence.getCreatedAt()).isNotNull();
                        }));
    }

    private void assertBomProcessedNotification() throws Exception {
        try {
            assertThat(qm.getNotificationOutbox()).anySatisfy(
                    notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));
        } catch (AssertionError e) {
            final Optional<Notification> optionalNotification = qm.getNotificationOutbox().stream()
                    .filter(notification -> notification.getGroup() == GROUP_BOM_PROCESSING_FAILED)
                    .findAny();
            if (optionalNotification.isEmpty()) {
                throw e;
            }

            final var subject = optionalNotification.get().getSubject().unpack(BomProcessingFailedSubject.class);
            fail("Expected BOM processing to succeed, but it failed due to: %s", subject.getCause());
        }
    }

    private FileMetadata storeBomFile(final String testFileName) throws Exception {
        final Path bomFilePath = Paths.get(resourceToURL("/unit/" + testFileName).toURI());

        try (final var fileInputStream = Files.newInputStream(bomFilePath)) {
            return fileStorage.store(
                    "test/%s-%s".formatted(ImportBomActivityTest.class.getSimpleName(), UUID.randomUUID()),
                    fileInputStream);
        }
    }

    private FileMetadata storeBomFile(final byte[] bomBytes) throws Exception {
        return fileStorage.store(
                "test/%s-%s".formatted(ImportBomActivityTest.class.getSimpleName(), UUID.randomUUID()),
                new ByteArrayInputStream(bomBytes));
    }

}
