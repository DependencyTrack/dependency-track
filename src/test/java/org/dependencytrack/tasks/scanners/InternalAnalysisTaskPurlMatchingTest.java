package org.dependencytrack.tasks.scanners;


import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Arrays;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;


public class InternalAnalysisTaskPurlMatchingTest extends PersistenceCapableTest {

    public static Collection<Arguments> parameters() {
        return Arrays.asList(

            Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources", WITHOUT_RANGE, MATCHES, "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"),
            Arguments.of("pkg:npm/foobar@12.3.1", WITHOUT_RANGE, MATCHES, "pkg:npm/foobar@12.3.1"), 


            Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim", WITHOUT_RANGE, MATCHES, "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"),
            Arguments.of("pkg:npm/foobar", WITHOUT_RANGE, MATCHES, "pkg:npm/foobar@12.3.1"),


            Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim", Range.withRange().havingStartIncluding("1.5.0").havingEndExcluding("2.0.0"), MATCHES, "pkg:maven/org.apache.xmlgraphics/batik-anim@1.8.0"),
            Arguments.of("pkg:npm/foobar", Range.withRange().havingStartExcluding("10.0.0").havingEndIncluding("15.0.0"), MATCHES, "pkg:npm/foobar@12.3.1"),

            Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1", WITHOUT_RANGE, DOES_NOT_MATCH, "pkg:npm/org.apache.xmlgraphics/batik-anim@1.9.1"),

            Arguments.of("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1", WITHOUT_RANGE, DOES_NOT_MATCH, "pkg:maven/com.example/batik-anim@1.9.1")

        );
    }

    public record Range(String startIncluding, String startExcluding, String endIncluding, String endExcluding) {

        public static Range withRange() {
            return new Range(null, null, null, null);
        }

        public Range havingStartIncluding(final String startIncluding) {
            return new Range(startIncluding, this.startExcluding, this.endIncluding, this.endExcluding);
        }

        public Range havingStartExcluding(final String startExcluding) {
            return new Range(this.startIncluding, startExcluding, this.endIncluding, this.endExcluding);
        }

        public Range havingEndIncluding(final String endIncluding) {
            return new Range(this.startIncluding, this.startExcluding, endIncluding, this.endExcluding);
        }

        public Range havingEndExcluding(final String endExcluding) {
            return new Range(this.startIncluding, this.startExcluding, this.endIncluding, endExcluding);
        }

    }

    private static final boolean MATCHES = true;
    private static final boolean DOES_NOT_MATCH = false;
    private static final Range WITHOUT_RANGE = null;

    @BeforeEach
    public void setUp() throws Exception {
        qm.createConfigProperty(
                SCANNER_INTERNAL_ENABLED.getGroupName(),
                SCANNER_INTERNAL_ENABLED.getPropertyName(),
                "true",
                SCANNER_INTERNAL_ENABLED.getPropertyType(),
                SCANNER_INTERNAL_ENABLED.getDescription()
        );
    }

    @ParameterizedTest(name = "[{index}] expect={2} src={0} range={1} target={3}")
    @MethodSource("parameters")
    void test(final String sourcePurlString,
              final Range sourceRange,
              final boolean expectMatch,
              final String targetPurlString) throws Exception {

        final VulnerableSoftware vs = ModelConverter.convertPurlToVulnerableSoftware(sourcePurlString);

        if (sourceRange != null) {
            Optional.ofNullable(sourceRange.startIncluding).ifPresent(vs::setVersionStartIncluding);
            Optional.ofNullable(sourceRange.startExcluding).ifPresent(vs::setVersionStartExcluding);
            Optional.ofNullable(sourceRange.endIncluding).ifPresent(vs::setVersionEndIncluding);
            Optional.ofNullable(sourceRange.endExcluding).ifPresent(vs::setVersionEndExcluding);
        }
        vs.setVulnerable(true);
        qm.persist(vs);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setVulnerableSoftware(List.of(vs));
        qm.persist(vuln);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(targetPurlString);;
        qm.persist(component);

        new InternalAnalysisTask().inform(new InternalAnalysisEvent(
                List.of(component), VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        if (expectMatch) {
            assertThat(qm.getAllVulnerabilities(component)).hasSize(1);
        } else {
            assertThat(qm.getAllVulnerabilities(component)).isEmpty();
        }
    }


}
