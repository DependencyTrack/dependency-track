package org.dependencytrack.util;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class ComponentVersionTest {
    @Test
    public void testSimple() {
        ComponentVersion version1 = new ComponentVersion("1.0.0");
        ComponentVersion version2 = new ComponentVersion("2.0.0");

        Assert.assertEquals(-1, version1.compareTo(version2));
    }
}

