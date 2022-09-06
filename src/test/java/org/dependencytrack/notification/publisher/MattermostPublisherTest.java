package org.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.http.HttpHeaders;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import javax.json.Json;
import javax.json.JsonObject;

import java.io.IOException;

import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class MattermostPublisherTest extends PersistenceCapableTest implements NotificationTestConfigProvider {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        mockServer = startClientAndServer(1080);
    }

    @AfterClass
    public static void afterClass() {
        mockServer.stop();
    }

    @Test
    public void testPublish() throws IOException {
        new MockServerClient("localhost", 1080)
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/mychannel")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                );
        JsonObject config = getConfig(DefaultNotificationPublishers.MATTERMOST, "http://localhost:1080/mychannel");
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        notification.setTitle("Test Notification");
        notification.setContent("This is only a test");
        MattermostPublisher publisher = new MattermostPublisher();
        publisher.inform(notification, config);
    }
}
