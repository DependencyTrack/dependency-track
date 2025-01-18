package org.dependencytrack.util;

import com.github.packageurl.PackageURL;
import org.junit.Assert;
import org.junit.Test;

public class EnvironmentFactoryTest {
    @Test
    public void testDebian() {
        Ecosystem ecosystem1 = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);
        Ecosystem ecosystem2 = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);

        Assert.assertTrue(ecosystem1 == ecosystem2);
    }

    @Test
    public void testUnknownMappedToGeneric() {
        Ecosystem ecosystem1 = EcosystemFactory.getEcosystem("unknown");
        Ecosystem ecosystem2 = EcosystemFactory.getEcosystem("unknown");

        Assert.assertTrue(ecosystem1 == ecosystem2);
        Assert.assertEquals(ecosystem1.getName(), PackageURL.StandardTypes.GENERIC);
    }
}

