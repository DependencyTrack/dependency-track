package org.dependencytrack.util;

import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.junit.Test;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

public class VulnerabilityUtilTest {

    @Test
    public void testGetUniqueAliases() {
        final var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setAliases(List.of(
                createAlias(alias -> {
                    alias.setInternalId("INTERNAL-001");
                    alias.setGhsaId("GHSA-002");
                    alias.setSonatypeId("SONATYPE-003");
                }),
                createAlias(alias -> {
                    alias.setInternalId("INTERNAL-001");
                    alias.setOsvId("OSV-004");
                    alias.setSonatypeId("SONATYPE-003");
                })
        ));

        final Set<Map.Entry<Vulnerability.Source, String>> uniqueAliases = VulnerabilityUtil.getUniqueAliases(vuln);
        assertThat(uniqueAliases).hasSize(3);
        assertThat(uniqueAliases).contains(new AbstractMap.SimpleEntry<>(Vulnerability.Source.GITHUB, "GHSA-002"));
        assertThat(uniqueAliases).contains(new AbstractMap.SimpleEntry<>(Vulnerability.Source.OSSINDEX, "SONATYPE-003"));
        assertThat(uniqueAliases).contains(new AbstractMap.SimpleEntry<>(Vulnerability.Source.OSV, "OSV-004"));
    }

    @Test
    public void testGetUniqueAliasesWhenVulnerabilityIsNull() {
        assertThat(VulnerabilityUtil.getUniqueAliases(null)).isEmpty();
    }

    @Test
    public void testGetUniqueAliasesWhenAliasesAreNull() {
        assertThat(VulnerabilityUtil.getUniqueAliases(new Vulnerability())).isEmpty();
    }

    private VulnerabilityAlias createAlias(final Consumer<VulnerabilityAlias> customizer) {
        final var alias = new VulnerabilityAlias();
        customizer.accept(alias);
        return alias;
    }

}