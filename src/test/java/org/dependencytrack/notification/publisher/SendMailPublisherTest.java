package org.dependencytrack.notification.publisher;

import javax.json.Json;
import javax.json.JsonObject;

import org.junit.Assert;
import org.junit.Test;

public class SendMailPublisherTest {
  private static JsonObject configWithDestination(final String destination) {
    return Json.createObjectBuilder().add("destination", destination).build();
  }


  @Test
  public void testSingleDestination() {
    JsonObject config = configWithDestination("john@doe.com");
    Assert.assertArrayEquals(new String[] { "john@doe.com" }, SendMailPublisher.parseDestination(config));
  }


  @Test
  public void testMultipleDestinations() {
    JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
    Assert.assertArrayEquals(new String[] { "john@doe.com", "steve@jobs.org" },
                             SendMailPublisher.parseDestination(config));
  }


  @Test
  public void testEmptyDestinations() {
    JsonObject config = configWithDestination("");
    Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config));
  }

}
