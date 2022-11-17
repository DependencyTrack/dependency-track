package org.dependencytrack.model;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class AliasAttributionTest extends PersistenceCapableTest {

    @Test
    public void testAliasAttributionUpdate() {

        // Snyk reports SNYK-123 to alias CVE-123
        qm.updateAliasAttribution("SNYK-123", "CVE-123", Vulnerability.Source.SNYK);

        // GitHub reports GHSA-123 to alias CVE-123
        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.GITHUB);

        // OSV reports the same GHSA-123 to alias CVE-123
        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.OSV);

        // OSV reports another CVE alias CVE-456 for GHSA-123
        qm.updateAliasAttribution("GHSA-123", "CVE-456", Vulnerability.Source.OSV);

        // OSV reports another alias CVE-456 for OSV-123
        qm.updateAliasAttribution("OSV-123", "CVE-456", Vulnerability.Source.OSV);

        // OSV reports the same GHSA-123 to alias CVE-123 again to change last seen
        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.OSV);

        List<AliasAttribution> aliasAttributions = qm.getAllAliasAttributions();
        Assert.assertNotNull(aliasAttributions);
        Assert.assertEquals(5, aliasAttributions.size());

        aliasAttributions = qm.getAliasAttributionsById("GHSA-123");
        Assert.assertNotNull(aliasAttributions);
        Assert.assertEquals(3, aliasAttributions.size());
    }

    @Test
    public void testAliasAttributionDelete() {

        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.GITHUB);
        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.OSV);
        qm.updateAliasAttribution("GHSA-123", "CVE-456", Vulnerability.Source.OSV);

        List<AliasAttribution> aliasAttributions = qm.getAllAliasAttributions();
        Assert.assertEquals(3, aliasAttributions.size());

        qm.deleteAliasAttribution(qm.getAliasAttributionById("GHSA-123", "CVE-123", Vulnerability.Source.OSV));
        aliasAttributions = qm.getAllAliasAttributions();
        Assert.assertEquals(2, aliasAttributions.size());
    }
}
