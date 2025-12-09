package org.dependencytrack.tasks;

import alpine.notification.Notification;
import alpine.notification.NotificationService;
import alpine.notification.Subscription;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.VexUploadEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;



public class VexUploadProcessingTaskTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements alpine.notification.Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @BeforeEach
    public void setUp() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));

        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());
    }

    @AfterEach
    public void tearDown() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
        NOTIFICATIONS.clear();
    }

    @Test
    void informTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        final byte[] vexBytes = resourceToByteArray("/vex-1.json");

        new VexUploadProcessingTask().inform(new VexUploadEvent(project.getUuid(), vexBytes));
        await().atMost(Duration.ofSeconds(5)).untilAsserted(
                () -> assertThat(NOTIFICATIONS).anyMatch(n -> NotificationGroup.VEX_CONSUMED.name().equals(n.getGroup())
                        && NotificationScope.PORTFOLIO.name().equals(n.getScope())));
        await().atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(NOTIFICATIONS)
                        .anyMatch(n -> NotificationGroup.VEX_PROCESSED.name().equals(n.getGroup())
                                && NotificationScope.PORTFOLIO.name().equals(n.getScope())));

    }
}
