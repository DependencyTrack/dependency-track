package org.dependencytrack.event;

import static org.junit.Assert.assertEquals;

import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;

public class ProjectCreationEventTest {
    
    @Test
    public void testConstructor() {
        UUID uuid = UUID.randomUUID();
        String name = "testing";
        ProjectCreationEvent event = new ProjectCreationEvent(uuid, name);
        Assert.assertEquals(uuid, event.getProjectUuid());
        assertEquals(name, event.getProjectName());
    }
}
