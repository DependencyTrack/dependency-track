package org.dependencytrack.util;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import jakarta.json.JsonObject;
import org.dependencytrack.PersistenceCapableTest;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityUpdateDiff;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.ProjectVulnerabilityUpdate;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class NotificationUtilTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @BeforeClass
    public static void setUpClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationUtilTest.NotificationSubscriber.class));
    }

    @AfterClass
    public static void tearDownClass() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationUtilTest.NotificationSubscriber.class));
    }

    @Before
    public void setup() {
        NOTIFICATIONS.clear();
    }

    @After
    public void tearDown() {
        NOTIFICATIONS.clear();
    }

    @Test
    public void testVulnerabilityUpdateNoAffectedComponents() {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2024-12345");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(vulnerability, false);

        final VulnerabilityUpdateDiff vulnerabilityUpdateDiff = new VulnerabilityUpdateDiff(Severity.UNASSIGNED, vulnerability.getSeverity());

        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, vulnerabilityUpdateDiff);

        // The Awaitility API is a bit awkward for asserting that something did not happen.
        // Here we wait for 3 continuous seconds (out of the 4s timeout period) where there is no vuln update notification
        // and fail early if we do find one. Due to the polling implementation atMost must be > the 'during' internal or
        // we will trigger a timeout and fail the test.
        org.awaitility.core.ThrowingRunnable assertion = (
                () -> assertThat(NOTIFICATIONS).extracting(Notification::getGroup).doesNotContain(NotificationGroup.PROJECT_VULNERABILITY_UPDATED.name())
        );
        await().during(Duration.ofSeconds(3)).atMost(Duration.ofSeconds(4))
                .failFast(assertion)
                .untilAsserted(assertion);
    }

    @Test
    public void testVulnerabilityUpdateMultipleComponents() {
        final Project projectA = qm.createProject("Project A", null, "1.0", null, null, null, true, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("Component A");
        componentA.setPurl("pkg:npm/foo@1.0.0");
        componentA = qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("Project B", null, "1.0", null, null, null, true, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("Component B");
        componentB.setPurl("pkg:npm/foo@1.0.0"); // same purl
        componentB = qm.createComponent(componentB, false);

        final ArrayList<Component> components = new ArrayList<>();
        components.add(componentA);
        components.add(componentB);

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2024-12345");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.CRITICAL);
        vulnerability.setComponents(components);
        qm.createVulnerability(vulnerability, false);

        final VulnerabilityUpdateDiff vulnerabilityUpdateDiff = new VulnerabilityUpdateDiff(Severity.UNASSIGNED, vulnerability.getSeverity());

        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, vulnerabilityUpdateDiff);

        // During the waiting period we expect no more than one vuln update notification
        org.awaitility.core.ThrowingRunnable assertNoMoreThanOneNotification = (
                () -> assertThat(NOTIFICATIONS)
                        .filteredOn(notification -> notification.getGroup().equals(NotificationGroup.PROJECT_VULNERABILITY_UPDATED.name()))
                        .hasSizeLessThanOrEqualTo(1)
        );
        await().during(Duration.ofSeconds(3)).atMost(Duration.ofSeconds(4))
                .failFast(assertNoMoreThanOneNotification)
                .untilAsserted(assertNoMoreThanOneNotification);

        // After the waiting period we expect exactly one vuln update notification
        assertThat(NOTIFICATIONS)
                .filteredOn(notification -> notification.getGroup().equals(NotificationGroup.PROJECT_VULNERABILITY_UPDATED.name()))
                .hasSize(1)
                .satisfiesExactly(notification -> {
                    assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
                    assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_VULNERABILITY_UPDATED.name());
                    assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
                    assertThat(notification.getSubject()).isInstanceOf(ProjectVulnerabilityUpdate.class);
                    final var subject = (ProjectVulnerabilityUpdate) notification.getSubject();
                    assertThat(components.stream().map(Component::getUuid).toList()).contains(subject.getComponent().getUuid());
                    assertThat(subject.getVulnerability().getUuid()).isEqualTo(vulnerability.getUuid());
                    assertThat(subject.getVulnerabilityUpdateDiff().getOldSeverity()).isEqualTo(vulnerabilityUpdateDiff.getOldSeverity());
                    assertThat(subject.getVulnerabilityUpdateDiff().getNewSeverity()).isEqualTo(vulnerabilityUpdateDiff.getNewSeverity());
                });
    }

    @Test
    public void testVulnerabilityUpdateToJson() {
        final Project project = qm.createProject("Project A", null, "1.0", null, null, null, true, false);
        var component = new Component();
        component.setProject(project);
        component.setName("Component A");
        component.setPurl("pkg:npm/foo@1.0.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2024-12345");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.CRITICAL);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability, false);

        final VulnerabilityUpdateDiff vulnerabilityUpdateDiff = new VulnerabilityUpdateDiff(Severity.UNASSIGNED, vulnerability.getSeverity());

        final ProjectVulnerabilityUpdate vo = new ProjectVulnerabilityUpdate(vulnerability, vulnerabilityUpdateDiff, component);
        final JsonObject subjectJson = NotificationUtil.toJson(vo);

        final String expectedJson = String.format(
                "{\"vulnerability\":{\"uuid\":\"%s\",\"vulnId\":\"%s\",\"source\":\"%s\",\"aliases\":[],"
                + "\"old\":{\"severity\":\"%s\"},\"new\":{\"severity\":\"%s\"}},"
                + "\"component\":{\"uuid\":\"%s\",\"name\":\"%s\",\"purl\":\"%s\"}}",
                vulnerability.getUuid(),
                vulnerability.getVulnId(),
                vulnerability.getSource(),
                vulnerabilityUpdateDiff.getOldSeverity(),
                vulnerabilityUpdateDiff.getNewSeverity(),
                component.getUuid(),
                component.getName(),
                component.getPurl()
        );

        assertThat(subjectJson).isNotNull();
        assertThat(subjectJson.toString()).isEqualTo(expectedJson);
    }
}
