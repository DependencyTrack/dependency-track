package org.dependencytrack.util;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.Test;

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
}
