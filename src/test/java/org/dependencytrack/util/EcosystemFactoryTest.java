package org.dependencytrack.util;

import com.github.packageurl.PackageURL;
import org.junit.Assert;
import org.junit.Test;

public class EcosystemFactoryTest {
    @Test
    public void testDebian() {
        Ecosystem ecosystem1 = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);
        Ecosystem ecosystem2 = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);

        Assert.assertTrue((Object)ecosystem1 == (Object)ecosystem2);
    }

    @Test
    public void testUnknownMappedToGeneric() {
        Ecosystem ecosystem1 = EcosystemFactory.getEcosystem("unknown");
        Ecosystem ecosystem2 = EcosystemFactory.getEcosystem("unknown");

        Assert.assertTrue((Object)ecosystem1 == (Object)ecosystem2);
        Assert.assertEquals(ecosystem1.getName(), PackageURL.StandardTypes.GENERIC);
    }
}

