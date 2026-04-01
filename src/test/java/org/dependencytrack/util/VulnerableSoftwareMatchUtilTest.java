package org.dependencytrack.util;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class VulnerableSoftwareMatchUtilTest {

    @Test
    void shouldMatchEscapedCpeComponentImmediately() {
        final var vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:microsoft:visual_c\\+\\+_redistributable:14.40.33810:*:*:*:*:*:x86:*");
        vs.setPart("a");
        vs.setVendor("microsoft");
        vs.setProduct("visual_c++_redistributable");
        vs.setVersion("14.40.33810");
        final var component = new Component();
        component.setCpe("cpe:2.3:a:microsoft:visual_c\\+\\+_redistributable:14.40.33810:*:*:*:*:*:x86:*");

        assertThat(VulnerableSoftwareMatchUtil.extractComparableVersion(component)).isEqualTo("14.40.33810");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isTrue();
    }

    @Test
    void shouldMatchPurlByStructuredCoordinates() {
        final var vs = new VulnerableSoftware();
        vs.setPurl("pkg:maven/com.example/demo@1.2.3?classifier=sources");
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("demo");
        vs.setPurlVersion("1.2.3");
        vs.setVersion("1.2.3");

        final var component = new Component();
        component.setPurl("pkg:maven/com.example/demo@1.2.3");

        assertThat(VulnerableSoftwareMatchUtil.matchesPurl(vs, component)).isTrue();
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isTrue();
    }

    @Test
    void shouldRejectPurlWhenVersionDoesNotMatch() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("left-pad");
        vs.setPurlVersion("1.3.0");
        vs.setVersion("1.3.0");

        final var component = new Component();
        component.setPurl("pkg:npm/left-pad@1.2.0");

        assertThat(VulnerableSoftwareMatchUtil.matchesPurl(vs, component)).isTrue();
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    @Test
    void shouldNormalizeVPrefixedComponentVersion() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("golang");
        vs.setPurlNamespace("example.com/acme");
        vs.setPurlName("module");
        vs.setVersion("1.2.3");

        final var component = new Component();
        component.setPurl("pkg:golang/example.com/acme/module@v1.2.3");

        assertThat(VulnerableSoftwareMatchUtil.extractComparableVersion(component)).isEqualTo("1.2.3");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isTrue();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF001 — Null / missing identity guard-rails
    // ─────────────────────────────────────────────────────────────────────────────

    /** TC-R1-01: null VS must not throw and must return false. */
    @Test
    void isAffected_nullVulnerableSoftware_returnsFalse() {
        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.17.21");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(null, component)).isFalse();
    }

    /** TC-R1-02: null Component must not throw and must return false. */
    @Test
    void isAffected_nullComponent_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        vs.setVersion("4.17.21");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, null)).isFalse();
    }

    /** TC-R1-03: Component with no PURL and no CPE must return false (no version identity). */
    @Test
    void isAffected_componentWithNoIdentity_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        vs.setVersion("4.17.21");

        final var component = new Component();
        component.setVersion("4.17.21"); // version present but no PURL/CPE
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF001 — PURL version range (startIncluding / endExcluding)
    // ─────────────────────────────────────────────────────────────────────────────

    /** TC-R1-04: Component version inside affected range → match. */
    @Test
    void isAffected_purlVersionInsideRange_returnsTrue() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        vs.setVersionStartIncluding("4.17.0");
        vs.setVersionEndExcluding("4.17.22");

        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.17.10");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isTrue();
    }

    /** TC-R1-05: Component at lower boundary (startIncluding) → match. */
    @Test
    void isAffected_purlVersionAtLowerBoundary_returnsTrue() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        vs.setVersionStartIncluding("4.17.0");
        vs.setVersionEndExcluding("4.17.22");

        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.17.0");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isTrue();
    }

    /** TC-R1-06: Component at upper boundary (endExcluding) → no match. */
    @Test
    void isAffected_purlVersionAtUpperBoundaryExcluded_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        vs.setVersionStartIncluding("4.17.0");
        vs.setVersionEndExcluding("4.17.22");

        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.17.22");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    /** TC-R1-07: Component version below range → no match. */
    @Test
    void isAffected_purlVersionBelowRange_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        vs.setVersionStartIncluding("4.17.0");
        vs.setVersionEndExcluding("4.17.22");

        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.16.9");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF001 — PURL name / namespace / type mismatch
    // ─────────────────────────────────────────────────────────────────────────────

    /** TC-R1-08: Different package name → no match even if version is identical. */
    @Test
    void isAffected_purlDifferentName_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("underscore");
        vs.setVersion("4.17.21");

        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.17.21");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    /** TC-R1-09: Different ecosystem type → no match. */
    @Test
    void isAffected_purlDifferentType_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlName("lodash");
        vs.setVersion("4.17.21");

        final var component = new Component();
        component.setPurl("pkg:npm/lodash@4.17.21");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF001 — CPE version range
    // ─────────────────────────────────────────────────────────────────────────────

    /** TC-R1-10: CPE component inside affected version range → match (Log4Shell scenario). */
    @Test
    void isAffected_cpeComponentInsideRange_returnsTrue() {
        final var vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
        vs.setPart("a");
        vs.setVendor("apache");
        vs.setProduct("log4j");
        vs.setVersionStartIncluding("2.0.0");
        vs.setVersionEndExcluding("2.15.0");

        final var component = new Component();
        component.setCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isTrue();
    }

    /** TC-R1-11: CPE component at patched version (endExcluding) → no match. */
    @Test
    void isAffected_cpePatchedVersionNotAffected_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
        vs.setPart("a");
        vs.setVendor("apache");
        vs.setProduct("log4j");
        vs.setVersionStartIncluding("2.0.0");
        vs.setVersionEndExcluding("2.15.0");

        final var component = new Component();
        component.setCpe("cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    /** TC-R1-12: CPE different vendor → no match. */
    @Test
    void isAffected_cpeDifferentVendor_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:microsoft:log4j:*:*:*:*:*:*:*:*");
        vs.setPart("a");
        vs.setVendor("microsoft");
        vs.setProduct("log4j");
        vs.setVersionStartIncluding("2.0.0");
        vs.setVersionEndExcluding("2.15.0");

        final var component = new Component();
        component.setCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
        assertThat(VulnerableSoftwareMatchUtil.isAffected(vs, component)).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF001 — compareVersions edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    /** TC-R1-13: Wildcard VS version matches any component version. */
    @Test
    void compareVersions_wildcardMatchesAnyVersion() {
        final var vs = new VulnerableSoftware();
        vs.setVersion("*");
        assertThat(VulnerableSoftwareMatchUtil.compareVersions(vs, "99.99.99")).isTrue();
        assertThat(VulnerableSoftwareMatchUtil.compareVersions(vs, "0.0.1")).isTrue();
    }

    /** TC-R1-14: Null target version always returns false. */
    @Test
    void compareVersions_nullTargetVersion_returnsFalse() {
        final var vs = new VulnerableSoftware();
        vs.setVersion("1.0.0");
        assertThat(VulnerableSoftwareMatchUtil.compareVersions(vs, null)).isFalse();
    }

    /** TC-R1-15: Null VS returns false without exception. */
    @Test
    void compareVersions_nullVulnerableSoftware_returnsFalse() {
        assertThat(VulnerableSoftwareMatchUtil.compareVersions(null, "1.0.0")).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF001 — hasPurlIdentity / hasCpeIdentity
    // ─────────────────────────────────────────────────────────────────────────────

    /** TC-R1-16: VS with purlType + purlName is recognised as PURL identity. */
    @Test
    void hasPurlIdentity_withPurlTypeAndName_returnsTrue() {
        final var vs = new VulnerableSoftware();
        vs.setPurlType("npm");
        vs.setPurlName("lodash");
        assertThat(VulnerableSoftwareMatchUtil.hasPurlIdentity(vs)).isTrue();
    }

    /** TC-R1-17: VS with no PURL fields is NOT a PURL identity. */
    @Test
    void hasPurlIdentity_noFields_returnsFalse() {
        assertThat(VulnerableSoftwareMatchUtil.hasPurlIdentity(new VulnerableSoftware())).isFalse();
    }

    /** TC-R1-18: VS with cpe23 is recognised as CPE identity. */
    @Test
    void hasCpeIdentity_withCpe23_returnsTrue() {
        final var vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
        assertThat(VulnerableSoftwareMatchUtil.hasCpeIdentity(vs)).isTrue();
    }

    /** TC-R1-19: VS with vendor + product (no CPE string) is CPE identity. */
    @Test
    void hasCpeIdentity_withVendorAndProduct_returnsTrue() {
        final var vs = new VulnerableSoftware();
        vs.setVendor("apache");
        vs.setProduct("log4j");
        assertThat(VulnerableSoftwareMatchUtil.hasCpeIdentity(vs)).isTrue();
    }

    /** TC-R1-20: VS with no CPE fields is NOT a CPE identity. */
    @Test
    void hasCpeIdentity_noFields_returnsFalse() {
        assertThat(VulnerableSoftwareMatchUtil.hasCpeIdentity(new VulnerableSoftware())).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQF002 — Tracking status derivation helper (affectedProjectCount)
    // The tracking status is DERIVED at API level from affectedProjectCount:
    //   count > 0  → TRACKED, count == 0 → UNTRACKED, non-INTERNAL → UNDEFINED
    // These tests guard the extractComparableVersion path used to produce that count.
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * TC-R2-01: extractComparableVersion returns null for component with no version
     * → cannot match → affectedProjectCount stays 0 → status = UNTRACKED.
     */
    @Test
    void extractComparableVersion_componentWithNoVersion_returnsNull() {
        final var component = new Component();
        assertThat(VulnerableSoftwareMatchUtil.extractComparableVersion(component)).isNull();
    }

    /**
     * TC-R2-02: extractComparableVersion strips leading "v" for Go-style tags
     * → correct version comparison → component can be counted in affectedProjects.
     */
    @Test
    void extractComparableVersion_vPrefixedPurlVersion_stripped() {
        final var component = new Component();
        component.setPurl("pkg:golang/example.com/foo@v2.3.4");
        assertThat(VulnerableSoftwareMatchUtil.extractComparableVersion(component)).isEqualTo("2.3.4");
    }

    /**
     * TC-R2-03: extractComparableVersion prefers CPE version over PURL version
     * when both are set, ensuring consistent matching for CPE-identified VS entries.
     */
    @Test
    void extractComparableVersion_cpeVersionPreferredOverPurl() {
        final var component = new Component();
        // CPE says 14.40 but PURL says 14.40.33810
        component.setCpe("cpe:2.3:a:microsoft:visual_cpp:14.40:*:*:*:*:*:*:*");
        component.setPurl("pkg:nuget/vc_redist@14.40.33810");
        // CPE version wins
        assertThat(VulnerableSoftwareMatchUtil.extractComparableVersion(component)).isEqualTo("14.40");
    }
}
