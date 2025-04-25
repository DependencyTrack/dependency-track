package org.dependencytrack.persistence;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;

class ProjectQueryFilterBuilderTest {

    @Test
    void testEmptyBuilderBuildsEmptyFilter() {
        var builder = new ProjectQueryFilterBuilder();
        var filter = builder.buildFilter();
        Assertions.assertNotNull(filter);
        Assertions.assertTrue(filter.isEmpty());
    }

    @Test
    void testEmptyBuilderBuildsEmptyParams() {
        var builder = new ProjectQueryFilterBuilder();
        var params = builder.getParams();
        Assertions.assertNotNull(params);
        Assertions.assertTrue(params.isEmpty());
    }

    @Test
    void testBuilderBuildsFilterAndParams() {
        var testName = "test";
        var builder = new ProjectQueryFilterBuilder().withName(testName);
        Assertions.assertEquals(Map.of("name", testName), builder.getParams());
        Assertions.assertEquals("(name == :name)", builder.buildFilter());
    }

}
