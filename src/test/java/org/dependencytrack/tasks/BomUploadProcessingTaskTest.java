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

import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.model.IConfigProperty.PropertyType;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscription;
import org.awaitility.core.ConditionTimeoutException;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.NewVulnerableDependencyAnalysisEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import org.dependencytrack.search.document.ComponentDocument;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.fail;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_ENABLED;

public class BomUploadProcessingTaskTest extends PersistenceCapableTest {

    public static class EventSubscriber implements alpine.event.framework.Subscriber {

        @Override
        public void inform(final Event event) {
            EVENTS.add(event);
        }

    }

    public static class NotificationSubscriber implements alpine.notification.Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Event> EVENTS = new ConcurrentLinkedQueue<>();
    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @Before
    public void setUp() {
        EventService.getInstance().subscribe(IndexEvent.class, EventSubscriber.class);
        EventService.getInstance().subscribe(RepositoryMetaEvent.class, EventSubscriber.class);
        EventService.getInstance().subscribe(VulnerabilityAnalysisEvent.class, EventSubscriber.class);
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));

        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());

        // Enable internal vulnerability analyzer
        qm.createConfigProperty(ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getGroupName(),
                ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getPropertyName(), "true",
                ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getDescription());
    }

    @After
    public void tearDown() {
        EventService.getInstance().unsubscribe(EventSubscriber.class);
        EventService.getInstance().unsubscribe(VulnerabilityAnalysisTask.class);
        EventService.getInstance().unsubscribe(NewVulnerableDependencyAnalysisTask.class);
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));

        EVENTS.clear();
        NOTIFICATIONS.clear();
    }

    @Test
    public void informTest() throws Exception {
        EventService.getInstance().subscribe(VulnerabilityAnalysisEvent.class, VulnerabilityAnalysisTask.class);
        EventService.getInstance().subscribe(NewVulnerableDependencyAnalysisEvent.class, NewVulnerableDependencyAnalysisTask.class);

        for (final License license : new SpdxLicenseDetailParser().getLicenseDefinitions()) {
            if ("Apache-2.0".equals(license.getLicenseId())) {
                qm.synchronizeLicense(license, false);
            }
        }

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final VulnerableSoftware vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("xmlutil");
        vs.setVersion("1.0.0");
        vs.setVulnerable(true);

        final var vulnerability1 = new Vulnerability();
        vulnerability1.setVulnId("INT-001");
        vulnerability1.setSource(Vulnerability.Source.INTERNAL);
        vulnerability1.setSeverity(Severity.HIGH);
        vulnerability1.setVulnerableSoftware(List.of(vs));
        qm.createVulnerability(vulnerability1, false);

        final var vulnerability2 = new Vulnerability();
        vulnerability2.setVulnId("INT-002");
        vulnerability2.setSource(Vulnerability.Source.INTERNAL);
        vulnerability2.setSeverity(Severity.HIGH);
        vulnerability2.setVulnerableSoftware(List.of(vs));
        qm.createVulnerability(vulnerability2, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                resourceToByteArray("/unit/bom-1.xml"));
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getLastBomImport()).isNotNull();
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
        assertThat(component.getSupplier().getName()).isEqualTo("Foo Incorporated");
        assertThat(component.getSupplier().getUrls()[0]).isEqualTo("https://foo.bar.com");
        assertThat(component.getSupplier().getContacts().get(0).getEmail()).isEqualTo("foojr@bar.com");
        assertThat(component.getSupplier().getContacts().get(0).getPhone()).isEqualTo("123-456-7890");

        assertThat(component.getAuthor()).isEqualTo("Sometimes this field is long because it is composed of a list of authors......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................");
        assertThat(component.getPublisher()).isEqualTo("Example Incorporated");
        assertThat(component.getGroup()).isEqualTo("com.example");
        assertThat(component.getName()).isEqualTo("xmlutil");
        assertThat(component.getVersion()).isEqualTo("1.0.0");
        assertThat(component.getDescription()).isEqualTo("A makebelieve XML utility library");
        assertThat(component.getCpe()).isEqualTo("cpe:/a:example:xmlutil:1.0.0");
        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:maven/com.example/xmlutil@1.0.0?packaging=jar");
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

        assertThat(qm.getAllVulnerabilities(component)).hasSize(2);
        assertThat(NOTIFICATIONS).satisfiesExactly(
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name()),
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.BOM_CONSUMED.name()),
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.BOM_PROCESSED.name()),
                n -> {
                    assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name());
                    NewVulnerabilityIdentified nvi = (NewVulnerabilityIdentified) n.getSubject();
                    assertThat(nvi.getVulnerabilityAnalysisLevel()).isEqualTo(VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);
                },
                n -> {
                    assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name());
                    NewVulnerabilityIdentified nvi = (NewVulnerabilityIdentified) n.getSubject();
                    assertThat(nvi.getVulnerabilityAnalysisLevel()).isEqualTo(VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);
                },
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABLE_DEPENDENCY.name())
        );
    }

    @Test
    public void informWithEmptyBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                resourceToByteArray("/unit/bom-empty.json"));
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNotNull();

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();
    }

    @Test
    public void informWithInvalidCycloneDxBomTest() throws Exception {
        qm.createConfigProperty(
                BOM_VALIDATION_ENABLED.getGroupName(),
                BOM_VALIDATION_ENABLED.getPropertyName(),
                "true",
                BOM_VALIDATION_ENABLED.getPropertyType(),
                null
        );

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                """.getBytes(StandardCharsets.UTF_8);

        new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes));
        assertConditionWithTimeout(() -> NOTIFICATIONS.size() >= 2, Duration.ofSeconds(5));

        assertThat(NOTIFICATIONS).satisfiesExactly(
                notification -> assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name()),
                notification -> {
                    assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
                    assertThat(notification.getGroup()).isEqualTo(NotificationGroup.BOM_PROCESSING_FAILED.name());
                    assertThat(notification.getLevel()).isEqualTo(NotificationLevel.ERROR);
                    assertThat(notification.getTitle()).isNotBlank();
                    assertThat(notification.getContent()).isNotBlank();
                    assertThat(notification.getSubject()).isInstanceOf(BomProcessingFailed.class);
                    final var subject = (BomProcessingFailed) notification.getSubject();
                    assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid());
                    assertThat(subject.getBom()).isEqualTo("ewogICJib21Gb3JtYXQiOiAiQ3ljbG9uZURYIiwK");
                    assertThat(subject.getFormat()).isEqualTo(Bom.Format.CYCLONEDX);
                    assertThat(subject.getSpecVersion()).isNull();
                    assertThat(subject.getCause()).isEqualTo("Unable to parse BOM from byte array");
                }
        );

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNull();
    }

    @Test
    public void informWithNonExistentProjectTest() throws Exception {
        final Project project = new Project();
        project.setId(1);
        project.setUuid(UUID.randomUUID());
        project.setName("test-project");

        var bomUploadEvent = new BomUploadEvent(project, resourceToByteArray("/unit/bom-1.xml"));
        new BomUploadProcessingTask().inform(bomUploadEvent);

        await("BOM Processing Failed Notification")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    assertThat(NOTIFICATIONS).anySatisfy(notification -> {
                        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.BOM_PROCESSING_FAILED.name());
                    });
                });
    }

    @Test
    public void informWithComponentsUnderMetadataBomTest() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                resourceToByteArray("/unit/bom-metadata-components.json"));
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

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
    public void informWithExistingDuplicateComponentsTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setGroup("com.acme");
        componentA.setName("acme-lib");
        componentA.setVersion("2.0.0");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setGroup("com.acme");
        componentB.setName("acme-lib");
        componentB.setVersion("2.0.0");
        qm.persist(componentB);

        final Component transientComponentA = qm.makeTransient(componentA);
        final Component transientComponentB = qm.makeTransient(componentB);

        final byte[] bomBytes = """
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
                      "name": "acme-lib",
                      "version": "2.0.0"
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllComponents(project)).satisfiesExactly(c -> {
            assertThat(c.getId()).isEqualTo(componentA.getId());
            assertThat(c.getClassifier()).isEqualTo(Classifier.LIBRARY);
            assertThat(c.getPublisher()).isEqualTo("Acme Inc");
            assertThat(c.getGroup()).isEqualTo("com.acme");
            assertThat(c.getName()).isEqualTo("acme-lib");
            assertThat(c.getVersion()).isEqualTo("2.0.0");
        });

        assertThat(EVENTS).satisfiesExactlyInAnyOrder(
                event -> {
                    assertThat(event).isInstanceOf(IndexEvent.class);
                    final var indexEvent = (IndexEvent) event;
                    assertThat(indexEvent.getIndexableClass()).isEqualTo(Component.class);
                    assertThat(indexEvent.getAction()).isEqualTo(IndexEvent.Action.UPDATE);
                    final var searchDoc = (ComponentDocument) indexEvent.getDocument();
                    assertThat(searchDoc.uuid()).isEqualTo(transientComponentA.getUuid());
                },
                event -> {
                    assertThat(event).isInstanceOf(IndexEvent.class);
                    final var indexEvent = (IndexEvent) event;
                    assertThat(indexEvent.getIndexableClass()).isEqualTo(Component.class);
                    assertThat(indexEvent.getAction()).isEqualTo(IndexEvent.Action.DELETE);
                    final var searchDoc = (ComponentDocument) indexEvent.getDocument();
                    assertThat(searchDoc.uuid()).isEqualTo(transientComponentB.getUuid());
                },
                event -> {
                    assertThat(event).isInstanceOf(IndexEvent.class);
                    final var indexEvent = (IndexEvent) event;
                    assertThat(indexEvent.getIndexableClass()).isEqualTo(Project.class);
                    assertThat(indexEvent.getAction()).isEqualTo(IndexEvent.Action.UPDATE);
                },
                event -> assertThat(event).isInstanceOf(VulnerabilityAnalysisEvent.class),
                event -> assertThat(event).isInstanceOf(RepositoryMetaEvent.class)
        );
    }

    @Test
    public void informWithBloatedBomTest() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                resourceToByteArray("/unit/bom-bloated.json"));
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

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

    @Test
    public void informWithCustomLicenseResolutionTest() throws Exception {
        final var customLicense = new License();
        customLicense.setName("custom license foobar");
        qm.createCustomLicense(customLicense, false);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                resourceToByteArray("/unit/bom-custom-license.json"));
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

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
    public void informWithBomContainingLicenseExpressionTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final byte[] bomBytes = """
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
                      "name": "tomcat-catalina",
                      "version": "9.0.14",
                      "licenses": [
                        {
                          "expression": "EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0"
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isEqualTo("EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0");
            assertThat(component.getResolvedLicense()).isNull();
        });
    }

    @Test
    public void informWithBomContainingLicenseExpressionWithSingleIdTest() {
        final var license = new License();
        license.setLicenseId("EPL-2.0");
        license.setName("Eclipse Public License 2.0");
        qm.persist(license);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final byte[] bomBytes = """
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
                      "name": "tomcat-catalina",
                      "version": "9.0.14",
                      "licenses": [
                        {
                          "expression": "EPL-2.0"
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("EPL-2.0");
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isEqualTo("EPL-2.0");
        });
    }

    @Test
    public void informWithBomContainingInvalidLicenseExpressionTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final byte[] bomBytes = """
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
                      "name": "tomcat-catalina",
                      "version": "9.0.14",
                      "licenses": [
                        {
                          "expression": "(invalid"
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isNull();
            assertThat(component.getResolvedLicense()).isNull();
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3433
    public void informIssue3433Test() {
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

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("GPL-3.0-or-later");
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3498
    public void informUpdateExistingLicenseTest() {
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

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), existingBomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

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

        new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), updatedBomBytes));
        awaitBomProcessedNotification(bomUploadEvent);
        qm.getPersistenceManager().evictAll();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo(updatedLicense.getLicenseId());
        });

    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3498
    public void informDeleteExistingLicenseTest() {
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

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), existingBomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

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

        new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), updatedBomBytes));
        awaitBomProcessedNotification(bomUploadEvent);
        qm.getPersistenceManager().evictAll();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNull();
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseUrl()).isNull();
            assertThat(component.getLicenseExpression()).isNull();
        });
    }

    @Test
    public void informWithBomContainingServiceTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                resourceToByteArray("/unit/bom-service.json"));
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        assertThat(qm.getAllComponents(project)).isNotEmpty();
        assertThat(qm.getAllServiceComponents(project)).isNotEmpty();
    }

    @Test
    public void informWithExistingComponentPropertiesAndBomWithoutComponentProperties() {
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

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "name": "acme-lib"
                    }
                  ]
                }
                """.getBytes());
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getProperties()).isEmpty();
    }

    @Test
    public void informWithExistingComponentPropertiesAndBomWithComponentProperties() {
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

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), """
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
                          "value": "baz"
                        }
                      ]
                    }
                  ]
                }
                """.getBytes());
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        qm.getPersistenceManager().refresh(component);
        assertThat(component.getProperties()).satisfiesExactly(property -> {
            assertThat(property.getGroupName()).isNull();
            assertThat(property.getPropertyName()).isEqualTo("foo");
            assertThat(property.getPropertyValue()).isEqualTo("baz");
            assertThat(property.getUuid()).isNotEqualTo(componentProperty.getUuid());
        });
    }

    @Test
    public void informWithLicenseResolutionByNameTest() {
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
                            "name": "MIT License"
                          }
                        }
                      ]
                    }
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("MIT");
        });
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/1905
    public void informIssue1905Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        for (int i = 0; i < 3; i++) {
            var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                    resourceToByteArray("/unit/bom-issue1905.json"));
            new BomUploadProcessingTask().inform(bomUploadEvent);

            // Make sure processing did not fail.
            awaitBomProcessedNotification(bomUploadEvent);
            NOTIFICATIONS.clear();

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

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2519
    public void informIssue2519Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // Upload the same BOM again a few times.
        // Ensure processing does not fail, and the number of components ingested doesn't change.
        for (int i = 0; i < 3; i++) {
            var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                    resourceToByteArray("/unit/bom-issue2519.xml"));
            new BomUploadProcessingTask().inform(bomUploadEvent);

            // Make sure processing did not fail.
            awaitBomProcessedNotification(bomUploadEvent);
            NOTIFICATIONS.clear();

            // Ensure the expected amount of components is present.
            assertThat(qm.getAllComponents(project)).hasSize(1756);
        }
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2859
    public void informIssue2859Test() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final byte[] bomBytes = resourceToByteArray("/unit/bom-issue2859.xml");

        assertThatNoException()
                .isThrownBy(() -> new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes)));
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3309
    public void informIssue3309Test() {
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

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "metadata": {
                    "authors": [
                      {
                        "name": "Author Name",
                        "email": "author@example.com"
                      }
                    ]
                  }
                }
                """.getBytes();

        var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);
        assertProjectAuthors.run();

        NOTIFICATIONS.clear();

        bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);
        assertProjectAuthors.run();
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3371
    public void informIssue3371Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // Upload the same BOM again a few times.
        // Ensure processing does not fail, and the number of components ingested doesn't change.
        for (int i = 0; i < 2; i++) {
            var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()),
                    resourceToByteArray("/unit/bom-issue3371.json"));
            new BomUploadProcessingTask().inform(bomUploadEvent);

            // Make sure processing did not fail.
            awaitBomProcessedNotification(bomUploadEvent);
            NOTIFICATIONS.clear();

            // Ensure the expected amount of components is present.
            assertThat(qm.getAllComponents(project)).satisfiesExactlyInAnyOrder(
                    component -> {
                        assertThat(component.getName()).isEqualTo("alsa-utils");
                        assertThat(component.getVersion()).isEqualTo("1.2.1.2");
                        assertThat(component.getCpe()).isEqualTo("cpe:2.3:*:alsa-project:alsa:1.2.1.2:*:*:*:*:*:*:*");
                    },
                    component -> {
                        assertThat(component.getName()).isEqualTo("alsa-lib");
                        assertThat(component.getVersion()).isEqualTo("1.2.1.2");
                        assertThat(component.getCpe()).isEqualTo("cpe:2.3:*:alsa-project:alsa:1.2.1.2:*:*:*:*:*:*:*");
                    }
            );
        }
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3957
    public void informIssue3957Test() {
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

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("GPL-1.0");
        });
    }

    @Test
    public void informIssue3981Test() {
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

        var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);
        NOTIFICATIONS.clear();

        final Project clonedProject = qm.clone(project.getUuid(), "3.2.1", true, true, true, true, true, true, true);

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

        bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, clonedProject.getId()), bomBytes);
        new BomUploadProcessingTask().inform(bomUploadEvent);
        awaitBomProcessedNotification(bomUploadEvent);

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

    private void awaitBomProcessedNotification(final BomUploadEvent bomUploadEvent) {
        try {
            await("BOM Processed Notification")
                    .atMost(Duration.ofSeconds(3))
                    .untilAsserted(() -> assertThat(NOTIFICATIONS)
                            .anyMatch(n -> NotificationGroup.BOM_PROCESSED.name().equals(n.getGroup())
                                           && NotificationScope.PORTFOLIO.name().equals(n.getScope())));
        } catch (ConditionTimeoutException e) {
            final Optional<Notification> optionalNotification = NOTIFICATIONS.stream()
                    .filter(n -> NotificationGroup.BOM_PROCESSING_FAILED.name().equals(n.getGroup()))
                    .findAny();
            if (optionalNotification.isEmpty()) {
                throw e;
            }

            final var subject = (BomProcessingFailed) optionalNotification.get().getSubject();
            fail("Expected BOM processing to succeed, but it failed due to: %s", subject.getCause());
        }

        await("Event Processing Completion")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(Event.isEventBeingProcessed(bomUploadEvent.getChainIdentifier())).isFalse());
    }

}
