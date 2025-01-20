package org.dependencytrack.util;

import com.github.packageurl.PackageURL;
import java.util.ArrayList;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;

public class EcosystemTest {
    @Test
    public void testName() {
        Ecosystem ecosystem = new Ecosystem(PackageURL.StandardTypes.DEBIAN, new ArrayList(), "", new ArrayList());
        Assert.assertEquals(ecosystem.getName(), PackageURL.StandardTypes.DEBIAN);
    }

    @Test
    public void testTokenRegex() {
        Ecosystem ecosystem = new Ecosystem("test", List.of("a"), "#" , List.of("b"));
        Assert.assertEquals(ecosystem.getTokenRegex().toString(), "(a)|(#)|(\n)|(b)");
    }

    @Test
    public void testGetEndOfStringPriority() {
        Ecosystem ecosystem = new Ecosystem("test", List.of("a"), "#" , List.of("b"));
        int endOfStringPriority = ecosystem.getEndOfStringPriority();
        Assert.assertEquals(ecosystem.getTokenRegex().toString().split("\\|")[endOfStringPriority] , "(#)");
    }
}

