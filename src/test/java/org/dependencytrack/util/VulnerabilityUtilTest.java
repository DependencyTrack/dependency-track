package org.dependencytrack.util;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigDecimal;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
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

    @Test
    @Parameters(method = "cvss2ScoreSource")
    public void testNormalizedCvssV2Score(double score, Severity severity) {
        assertThat(VulnerabilityUtil.normalizedCvssV2Score(score)).isEqualTo(severity);
    }

    @Test
    @Parameters(method = "cvss3ScoreSource")
    public void testNormalizedCvssV3Score(double score, Severity severity) {
        assertThat(VulnerabilityUtil.normalizedCvssV3Score(score)).isEqualTo(severity);
    }

    @Test
    @Parameters(method = "owaspRRScoreSource")
    public void testNormalizedOwaspRRScore(double score, Severity severity) {
        assertThat(VulnerabilityUtil.normalizedOwaspRRScore(score)).isEqualTo(severity);
    }

    @Test
    @Parameters(method = "detailedOwaspRRScoreSource")
    public void testDetailedNormalizedOwaspRRScore(double likelihoodScore, double technicalImpactScore, double businessImpactScore, Severity severity) {
        assertThat(VulnerabilityUtil.normalizedOwaspRRScore(likelihoodScore, technicalImpactScore, businessImpactScore)).isEqualTo(severity);
    }

    @Test
    @Parameters(method = "cvssAndOwaspRRSeverity")
    public void testGetSeverity(BigDecimal cvssV2BaseScore, BigDecimal cvssV3BaseScore, BigDecimal owaspRRLikelihoodScore, BigDecimal owaspRRTechnicalImpactScore, BigDecimal owaspRRBusinessImpactScore, Severity severity) {
        assertThat(VulnerabilityUtil.getSeverity(cvssV2BaseScore, cvssV3BaseScore, owaspRRLikelihoodScore, owaspRRTechnicalImpactScore, owaspRRBusinessImpactScore)).isEqualTo(severity);
    }

    private VulnerabilityAlias createAlias(final Consumer<VulnerabilityAlias> customizer) {
        final var alias = new VulnerabilityAlias();
        customizer.accept(alias);
        return alias;
    }

    private Object[] cvss2ScoreSource() {
        return new Object[] {
            new Object[] { 8, Severity.HIGH },
            new Object[] { 5, Severity.MEDIUM },
            new Object[] { 2, Severity.LOW },
            new Object[] { 0, Severity.UNASSIGNED },
            new Object[] { Integer.MIN_VALUE, Severity.UNASSIGNED }
        };
    }

    private Object[] cvss3ScoreSource() {
        return new Object[] {
            new Object[] { 9, Severity.CRITICAL },
            new Object[] { 8, Severity.HIGH },
            new Object[] { 5, Severity.MEDIUM },
            new Object[] { 3, Severity.LOW },
            new Object[] { 0, Severity.UNASSIGNED },
            new Object[] { Integer.MIN_VALUE, Severity.UNASSIGNED }
        };
    }

    private Object[] owaspRRScoreSource() {
        return new Object[] {
            new Object[] { 10, Severity.HIGH },
            new Object[] { 7, Severity.HIGH },
            new Object[] { 4, Severity.MEDIUM },
            new Object[] { 2, Severity.LOW },
            new Object[] { 0, Severity.UNASSIGNED },
            new Object[] { Integer.MIN_VALUE, Severity.UNASSIGNED }
        };
    }

    private Object[] detailedOwaspRRScoreSource() {
        return new Object[] {
            new Object[] { 0.875, 1.25, 1.75, Severity.INFO },
            new Object[] { 5, 2.3, 2, Severity.LOW },
            new Object[] { 4.0, 2.75, 3.25, Severity.MEDIUM },
            new Object[] { 6.0, 4.75, 5, Severity.HIGH },
            new Object[] { 6.0, 15, 5, Severity.CRITICAL },
        };
    }

    private Object[] cvssAndOwaspRRSeverity() {
        return new Object[] {
            new Object[] { null, BigDecimal.valueOf(7.0), BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), Severity.HIGH },
            new Object[] { null, BigDecimal.valueOf(7.0), null, null, null, Severity.HIGH },
            new Object[] { null, null, BigDecimal.valueOf(5), BigDecimal.valueOf(2.3), BigDecimal.valueOf(2), Severity.LOW },
            new Object[] { BigDecimal.valueOf(7.0), null, BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), Severity.HIGH },
            new Object[] { BigDecimal.valueOf(7.0), null, BigDecimal.valueOf(6), BigDecimal.valueOf(15), BigDecimal.valueOf(5), Severity.CRITICAL },
        };
    }

}