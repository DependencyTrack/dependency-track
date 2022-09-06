package org.dependencytrack.resources.v1.vo;


import com.github.packageurl.PackageURL;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(Suite.class)
@SuiteClasses(value = {
        AffectedComponentTest.FromVulnerableSoftwareTest.class,
        AffectedComponentTest.ToVulnerableSoftwareTest.class
})
public class AffectedComponentTest {

    public static class FromVulnerableSoftwareTest {

        @Test
        public void shouldMapCpe22ToCpeIdentity() {
            final var vs = new VulnerableSoftware();
            vs.setCpe22("cpe:/a:apache:tomcat:7.0.27");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getIdentityType()).isEqualTo(AffectedComponent.IdentityType.CPE);
            assertThat(affectedComponent.getIdentity()).isEqualTo("cpe:/a:apache:tomcat:7.0.27");
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldMapCpe23ToCpeIdentity() {
            final var vs = new VulnerableSoftware();
            vs.setCpe23("cpe:2.3:a:apache:tomcat:7.0.27:*:*:*:*:*:*:*");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getIdentityType()).isEqualTo(AffectedComponent.IdentityType.CPE);
            assertThat(affectedComponent.getIdentity()).isEqualTo("cpe:2.3:a:apache:tomcat:7.0.27:*:*:*:*:*:*:*");
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldMapPurlToPurlIdentity() {
            final var vs = new VulnerableSoftware();
            vs.setPurl("pkg:golang/foo/bar@baz?ping=pong#1/2/3");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getIdentityType()).isEqualTo(AffectedComponent.IdentityType.PURL);
            assertThat(affectedComponent.getIdentity()).isEqualTo("pkg:golang/foo/bar@baz?ping=pong#1/2/3");
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldMapPurlFragmentsToPurlIdentity() {
            final var vs = new VulnerableSoftware();
            vs.setPurlType(PackageURL.StandardTypes.GOLANG);
            vs.setPurlNamespace("foo");
            vs.setPurlName("bar");
            vs.setPurlVersion("baz");
            vs.setPurlQualifiers("{\"ping\":\"pong\"}");
            vs.setPurlSubpath("1/2/3");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getIdentityType()).isEqualTo(AffectedComponent.IdentityType.PURL);
            assertThat(affectedComponent.getIdentity()).isEqualTo("pkg:golang/foo/bar@baz?ping=pong#1/2/3");
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldMapMinimalPurlPartsToPurlIdentity() {
            final var vs = new VulnerableSoftware();
            vs.setPurlType(PackageURL.StandardTypes.GOLANG);
            vs.setPurlNamespace("foo");
            vs.setPurlName("bar");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getIdentityType()).isEqualTo(AffectedComponent.IdentityType.PURL);
            assertThat(affectedComponent.getIdentity()).isEqualTo("pkg:golang/foo/bar");
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldIgnorePurlQualifiersWhenInvalid() {
            final var vs = new VulnerableSoftware();
            vs.setPurlType(PackageURL.StandardTypes.GOLANG);
            vs.setPurlNamespace("foo");
            vs.setPurlName("bar");
            vs.setPurlVersion("baz");
            vs.setPurlQualifiers("notJSON");
            vs.setPurlSubpath("1/2/3");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getIdentityType()).isEqualTo(AffectedComponent.IdentityType.PURL);
            assertThat(affectedComponent.getIdentity()).isEqualTo("pkg:golang/foo/bar@baz#1/2/3");
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldUseExactVersionWhenAvailable() {
            final var vs = new VulnerableSoftware();
            vs.setVersion("foo");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getVersionType()).isEqualTo(AffectedComponent.VersionType.EXACT);
            assertThat(affectedComponent.getVersion()).isEqualTo("foo");
            assertThat(affectedComponent.getVersionStartIncluding()).isNull();
            assertThat(affectedComponent.getVersionStartExcluding()).isNull();
            assertThat(affectedComponent.getVersionEndIncluding()).isNull();
            assertThat(affectedComponent.getVersionEndExcluding()).isNull();
        }

        @Test
        public void shouldUseVersionRangeWhenAvailable() {
            final var vs = new VulnerableSoftware();
            vs.setVersionStartIncluding("foo");
            vs.setVersionStartExcluding("bar");
            vs.setVersionEndIncluding("baz");
            vs.setVersionEndExcluding("qux");

            final var affectedComponent = new AffectedComponent(vs);
            assertThat(affectedComponent.getVersionType()).isEqualTo(AffectedComponent.VersionType.RANGE);
            assertThat(affectedComponent.getVersion()).isNull();
            assertThat(affectedComponent.getVersionStartIncluding()).isEqualTo("foo");
            assertThat(affectedComponent.getVersionStartExcluding()).isEqualTo("bar");
            assertThat(affectedComponent.getVersionEndIncluding()).isEqualTo("baz");
            assertThat(affectedComponent.getVersionEndExcluding()).isEqualTo("qux");
        }

    }

    public static class ToVulnerableSoftwareTest {

        @Test
        public void shouldMapCpe22Fields() {
            final var affectedComponent = new AffectedComponent();
            affectedComponent.setIdentityType(AffectedComponent.IdentityType.CPE);
            affectedComponent.setIdentity("cpe:/a:apache:tomcat:7.0.27");

            final VulnerableSoftware vs = affectedComponent.toVulnerableSoftware();
            assertThat(vs.getCpe22()).isEqualTo("cpe:/a:apache:tomcat:7.0.27");
            assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:apache:tomcat:7.0.27:*:*:*:*:*:*:*");
            assertThat(vs.getPart()).isEqualTo("a");
            assertThat(vs.getVendor()).isEqualTo("apache");
            assertThat(vs.getProduct()).isEqualTo("tomcat");
            assertThat(vs.getVersion()).isEqualTo("7.0.27");
            assertThat(vs.getVersionStartIncluding()).isNull();
            assertThat(vs.getVersionStartExcluding()).isNull();
            assertThat(vs.getVersionEndIncluding()).isNull();
            assertThat(vs.getVersionEndExcluding()).isNull();
            assertThat(vs.getUpdate()).isEqualTo("*");
            assertThat(vs.getEdition()).isEqualTo("*");
            assertThat(vs.getLanguage()).isEqualTo("*");
            assertThat(vs.getSwEdition()).isEqualTo("*");
            assertThat(vs.getTargetSw()).isEqualTo("*");
            assertThat(vs.getTargetHw()).isEqualTo("*");
            assertThat(vs.getOther()).isEqualTo("*");
            assertThat(vs.getPurl()).isNull();
            assertThat(vs.getPurlType()).isNull();
            assertThat(vs.getPurlNamespace()).isNull();
            assertThat(vs.getPurlName()).isNull();
            assertThat(vs.getPurlVersion()).isNull();
            assertThat(vs.getPurlQualifiers()).isNull();
            assertThat(vs.getPurlSubpath()).isNull();
        }

        @Test
        public void shouldReturnNullWhenCpeIsInvalid() {
            final var affectedComponent = new AffectedComponent();
            affectedComponent.setIdentityType(AffectedComponent.IdentityType.CPE);
            affectedComponent.setIdentity("invalid");

            final VulnerableSoftware vs = affectedComponent.toVulnerableSoftware();
            assertThat(vs).isNull();
        }

        @Test
        public void shouldMapCpe23Fields() {
            final var affectedComponent = new AffectedComponent();
            affectedComponent.setIdentityType(AffectedComponent.IdentityType.CPE);
            affectedComponent.setIdentity("cpe:2.3:a:apache:tomcat:7.0.27:*:*:*:*:*:*:*");

            final VulnerableSoftware vs = affectedComponent.toVulnerableSoftware();
            assertThat(vs.getCpe22()).isEqualTo("cpe:/a:apache:tomcat:7.0.27");
            assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:apache:tomcat:7.0.27:*:*:*:*:*:*:*");
            assertThat(vs.getPart()).isEqualTo("a");
            assertThat(vs.getVendor()).isEqualTo("apache");
            assertThat(vs.getProduct()).isEqualTo("tomcat");
            assertThat(vs.getVersion()).isEqualTo("7.0.27");
            assertThat(vs.getVersionStartIncluding()).isNull();
            assertThat(vs.getVersionStartExcluding()).isNull();
            assertThat(vs.getVersionEndIncluding()).isNull();
            assertThat(vs.getVersionEndExcluding()).isNull();
            assertThat(vs.getUpdate()).isEqualTo("*");
            assertThat(vs.getEdition()).isEqualTo("*");
            assertThat(vs.getLanguage()).isEqualTo("*");
            assertThat(vs.getSwEdition()).isEqualTo("*");
            assertThat(vs.getTargetSw()).isEqualTo("*");
            assertThat(vs.getTargetHw()).isEqualTo("*");
            assertThat(vs.getOther()).isEqualTo("*");
            assertThat(vs.getPurl()).isNull();
            assertThat(vs.getPurlType()).isNull();
            assertThat(vs.getPurlNamespace()).isNull();
            assertThat(vs.getPurlName()).isNull();
            assertThat(vs.getPurlVersion()).isNull();
            assertThat(vs.getPurlQualifiers()).isNull();
            assertThat(vs.getPurlSubpath()).isNull();
        }

        @Test
        public void shouldMapPurlFields() {
            final var affectedComponent = new AffectedComponent();
            affectedComponent.setIdentityType(AffectedComponent.IdentityType.PURL);
            affectedComponent.setIdentity("pkg:golang/foo/bar@baz?ping=pong#1/2/3");

            final VulnerableSoftware vs = affectedComponent.toVulnerableSoftware();
            assertThat(vs.getPurl()).isEqualTo("pkg:golang/foo/bar@baz?ping=pong#1/2/3");
            assertThat(vs.getPurlType()).isEqualTo(PackageURL.StandardTypes.GOLANG);
            assertThat(vs.getPurlNamespace()).isEqualTo("foo");
            assertThat(vs.getPurlName()).isEqualTo("bar");
            assertThat(vs.getPurlVersion()).isEqualTo("baz");
            assertThat(vs.getPurlQualifiers()).isEqualTo("{\"ping\":\"pong\"}");
            assertThat(vs.getPurlSubpath()).isEqualTo("1/2/3");
            assertThat(vs.getCpe22()).isNull();
            assertThat(vs.getCpe23()).isNull();
            assertThat(vs.getPart()).isNull();
            assertThat(vs.getVendor()).isNull();
            assertThat(vs.getProduct()).isNull();
            assertThat(vs.getVersion()).isEqualTo("baz");
            assertThat(vs.getVersionStartIncluding()).isNull();
            assertThat(vs.getVersionStartExcluding()).isNull();
            assertThat(vs.getVersionEndIncluding()).isNull();
            assertThat(vs.getVersionEndExcluding()).isNull();
            assertThat(vs.getUpdate()).isNull();
            assertThat(vs.getEdition()).isNull();
            assertThat(vs.getLanguage()).isNull();
            assertThat(vs.getSwEdition()).isNull();
            assertThat(vs.getTargetSw()).isNull();
            assertThat(vs.getTargetHw()).isNull();
            assertThat(vs.getOther()).isNull();
        }

        @Test
        public void shouldReturnNullWhenPurlIsInvalid() {
            final var affectedComponent = new AffectedComponent();
            affectedComponent.setIdentityType(AffectedComponent.IdentityType.PURL);
            affectedComponent.setIdentity("invalid");

            final VulnerableSoftware vs = affectedComponent.toVulnerableSoftware();
            assertThat(vs).isNull();
        }

        @Test
        public void shouldMapVersionRange() {
            final var affectedComponent = new AffectedComponent();
            affectedComponent.setVersionType(AffectedComponent.VersionType.RANGE);
            affectedComponent.setVersionStartIncluding("foo");
            affectedComponent.setVersionStartExcluding("bar");
            affectedComponent.setVersionEndIncluding("baz");
            affectedComponent.setVersionEndExcluding("qux");

            final VulnerableSoftware vs = affectedComponent.toVulnerableSoftware();
            assertThat(vs.getVersion()).isNull();
            assertThat(vs.getVersionStartIncluding()).isEqualTo("foo");
            assertThat(vs.getVersionStartExcluding()).isEqualTo("bar");
            assertThat(vs.getVersionEndIncluding()).isEqualTo("baz");
            assertThat(vs.getVersionEndExcluding()).isEqualTo("qux");
        }

    }

}