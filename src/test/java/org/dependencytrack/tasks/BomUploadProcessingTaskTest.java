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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.event.framework.EventService;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import net.jcip.annotations.NotThreadSafe;
import org.apache.commons.io.IOUtils;
import org.awaitility.core.ConditionTimeoutException;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.NewVulnerableDependencyAnalysisEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.fail;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

@NotThreadSafe
public class BomUploadProcessingTaskTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @Before
    public void setUp() {
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
        NOTIFICATIONS.clear();

        EventService.getInstance().unsubscribe(VulnerabilityAnalysisTask.class);
        EventService.getInstance().unsubscribe(NewVulnerableDependencyAnalysisTask.class);
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
    }

    @Test
    public void informTest() throws Exception {
        EventService.getInstance().subscribe(VulnerabilityAnalysisEvent.class, VulnerabilityAnalysisTask.class);
        EventService.getInstance().subscribe(NewVulnerableDependencyAnalysisEvent.class, NewVulnerableDependencyAnalysisTask.class);

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

        final byte[] bomBytes = Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("bom-1.xml").toURI()));

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
        assertConditionWithTimeout(() -> NOTIFICATIONS.size() >= 6, Duration.ofSeconds(5));

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

        assertThat(qm.getAllVulnerabilities(component)).hasSize(2);
        assertThat(NOTIFICATIONS).satisfiesExactly(
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name()),
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.BOM_CONSUMED.name()),
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.BOM_PROCESSED.name()),
                n -> {
                    assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name());
                    NewVulnerabilityIdentified nvi = (NewVulnerabilityIdentified) n.getSubject();
                    assertThat(nvi.getVulnerabilityAnalysisLevel().equals(VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));
                },
                n -> {
                    assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITY.name());
                    NewVulnerabilityIdentified nvi = (NewVulnerabilityIdentified) n.getSubject();
                    assertThat(nvi.getVulnerabilityAnalysisLevel().toString().equals(VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));
                },
                n -> assertThat(n.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABLE_DEPENDENCY.name())
        );
    }

    @Test
    public void informWithInvalidCycloneDxBomTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final byte[] bomBytes = """
                {
                  "bomFormat": "CycloneDX",
                """.getBytes(StandardCharsets.UTF_8);

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
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

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2859
    public void informIssue2859Test() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final byte[] bomBytes = IOUtils.resourceToByteArray("/unit/bom-issue2859.xml");

        assertThatNoException()
                .isThrownBy(() -> new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes)));
    }

    @Test
    public void informWithBomContainingLicenseExpressionTest() throws Exception {
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

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
        awaitBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isEqualTo("EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0");
            assertThat(component.getResolvedLicense()).isNull();
        });
    }

    @Test
    public void informWithBomContainingLicenseExpressionWithSingleIdTest() throws Exception {
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

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
        awaitBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getResolvedLicense()).isNotNull();
            assertThat(component.getResolvedLicense().getLicenseId()).isEqualTo("EPL-2.0");
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isEqualTo("EPL-2.0");
        });
    }

    @Test
    public void informWithBomContainingInvalidLicenseExpressionTest() throws Exception {
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

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
        awaitBomProcessedNotification();

        assertThat(qm.getAllComponents(project)).satisfiesExactly(component -> {
            assertThat(component.getLicense()).isNull();
            assertThat(component.getLicenseExpression()).isNull();
            assertThat(component.getResolvedLicense()).isNull();
        });
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

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
        awaitBomProcessedNotification();
        assertProjectAuthors.run();

        NOTIFICATIONS.clear();

        new BomUploadProcessingTask().inform(new BomUploadEvent(project.getUuid(), bomBytes));
        awaitBomProcessedNotification();
        assertProjectAuthors.run();
    }

    private void awaitBomProcessedNotification() {
        try {
            await("BOM Processed Notification")
                    .atMost(Duration.ofSeconds(3))
                    .untilAsserted(() -> assertThat(NOTIFICATIONS)
                            .anyMatch(n -> NotificationGroup.BOM_PROCESSED.name().equals(n.getGroup())));
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
    }

}
