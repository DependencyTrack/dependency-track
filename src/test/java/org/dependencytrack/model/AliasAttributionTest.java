package org.dependencytrack.model;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Test;

import javax.jdo.Query;
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

        List<VulnerabilityAliasAttribution> aliasAttributions = qm.getAliasAttributionsById("GHSA-123");
        Assert.assertNotNull(aliasAttributions);
        Assert.assertEquals(3, aliasAttributions.size());

        aliasAttributions = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                SELECT FROM org.dependencytrack.model.VulnerabilityAliasAttribution
                """).executeList();

        Assert.assertEquals(5, aliasAttributions.size());

    }

    @Test
    public void testAliasAttributionDelete() {

        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.GITHUB);
        qm.updateAliasAttribution("GHSA-123", "CVE-123", Vulnerability.Source.OSV);
        qm.updateAliasAttribution("GHSA-123", "CVE-456", Vulnerability.Source.OSV);

        List<VulnerabilityAliasAttribution> aliasAttributions = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                SELECT FROM org.dependencytrack.model.VulnerabilityAliasAttribution
                """).executeList();
        Assert.assertEquals(3, aliasAttributions.size());

        //qm.deleteAliasAttribution(
        VulnerabilityAliasAttribution aliasAttribution =  qm.getAliasAttributionById("GHSA-123", "CVE-123", Vulnerability.Source.OSV);
        final Query<?> query = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                DELETE FROM org.dependencytrack.model.VulnerabilityAliasAttribution
                WHERE vulnId == :vulnId && alias == :alias && source == :source
                """);
        query.execute(aliasAttribution.getVulnId(), aliasAttribution.getAlias(), aliasAttribution.getSource());
        aliasAttributions = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                SELECT FROM org.dependencytrack.model.VulnerabilityAliasAttribution
                """).executeList();
        Assert.assertEquals(2, aliasAttributions.size());
    }

}
