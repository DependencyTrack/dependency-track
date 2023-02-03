package org.dependencytrack.persistence;

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ProjectQueryFilterBuilderTest {

    @Test
    public void testEmptyBuilderBuildsEmptyFilter() {
        var builder = new ProjectQueryFilterBuilder();
        var filter = builder.buildFilter();
        assertNotNull(filter);
        assertTrue(filter.isEmpty());
    }

    @Test
    public void testEmptyBuilderBuildsEmptyParams() {
        var builder = new ProjectQueryFilterBuilder();
        var params = builder.getParams();
        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    @Test
    public void testBuilderBuildsFilterAndParams() {
        var testName = "test";
        var builder = new ProjectQueryFilterBuilder().withName(testName);
        assertEquals(Map.of("name", testName), builder.getParams());
        assertEquals("(name == :name)", builder.buildFilter());
    }

}
