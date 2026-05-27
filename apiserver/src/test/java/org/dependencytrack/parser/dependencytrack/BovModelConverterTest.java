/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.dependencytrack;

import com.google.protobuf.Timestamp;
import io.github.nscuro.versatile.Vers;
import org.cyclonedx.proto.v1_7.Advisory;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV2;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV3;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV31;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_CVSSV4;
import static org.cyclonedx.proto.v1_7.ScoreMethod.SCORE_METHOD_OWASP;

class BovModelConverterTest {

    @Test
    void testConvertNullValue() {
        assertThat(BovModelConverter.convert(Bom.newBuilder().build(), null, false)).isNull();
    }

    @Test
    void testConvert() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("CVE-2021-44228")
                        .setSource(Source.newBuilder().setName("NVD").build())
                        .setDescription("Foo Bar Description")
                        .setDetail("Foo Bar Baz Qux Quux")
                        .setRecommendation("Do this remedy as a fix")
                        .setCreated(Timestamp.newBuilder()
                                .setSeconds(1639098000)) // 2021-12-10
                        .setPublished(Timestamp.newBuilder()
                                .setSeconds(1639098000)) // 2021-12-10
                        .setUpdated(Timestamp.newBuilder()
                                .setSeconds(1675645200)) // 2023-02-06
                        .setRejected(Timestamp.newBuilder()
                                .setSeconds(1675645200)) // 2023-02-06
                        .addAllCwes(List.of(20, 400, 502, 917, 9999999)) // 9999999 is invalid
                        .addAdvisories(Advisory.newBuilder().setUrl("https://logging.apache.org/log4j/2.x/security.html").build())
                        .addAdvisories(Advisory.newBuilder().setUrl("https://support.apple.com/kb/HT213189").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV2)
                                .setScore(9.3)
                                .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(10.0)
                                .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("SNYK").build())
                                .setMethod(SCORE_METHOD_CVSSV3)
                                .setVector("snykVector"))
                        .addReferences(VulnerabilityReference.newBuilder()
                                .setId("SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720")
                                .setSource(Source.newBuilder().setName("SNYK").build()).build())
                        .addProperties(Property.newBuilder()
                                .setName(BovModelConverter.TITLE_PROPERTY_NAME)
                                .setValue("Foo Bar Title").build())
                        .build()).build();

        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln.getVulnId()).isEqualTo("CVE-2021-44228");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.NVD.name());
        assertThat(vuln.getTitle()).isEqualTo("Foo Bar Title");
        assertThat(vuln.getDescription()).isEqualTo("Foo Bar Description");
        assertThat(vuln.getDetail()).isEqualTo("Foo Bar Baz Qux Quux");
        assertThat(vuln.getRecommendation()).isEqualTo("Do this remedy as a fix");
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo(BigDecimal.valueOf(10.0));
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:M/Au:N/C:C/I:C/A:C)");
        assertThat(vuln.getCvssV2BaseScore()).isEqualTo(BigDecimal.valueOf(9.3));
        assertThat(vuln.getCreated()).isInSameDayAs("2021-12-10");
        assertThat(vuln.getPublished()).isInSameDayAs("2021-12-10");
        assertThat(vuln.getUpdated()).isInSameDayAs("2023-02-06");
        assertThat(vuln.getRejected()).isInSameDayAs("2023-02-06");
        assertThat(vuln.getReferences()).isEqualToIgnoringWhitespace("""
                * [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)\s
                * [https://support.apple.com/kb/HT213189](https://support.apple.com/kb/HT213189)
                """);
        assertThat(vuln.getCwes()).containsOnly(20, 400, 502, 917);
        assertThat(vuln.getAliases()).satisfiesExactly(
                alias -> {
                    assertThat(alias.getCveId()).isEqualTo("CVE-2021-44228");
                    assertThat(alias.getSnykId()).isEqualTo("SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720");
                }
        );
    }

    @Test
    void testConvertWithRatingFromSnykAsAuthoritativeSource() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("SNYK-PYTHON-DJANGO-2968205")
                        .setSource(Source.newBuilder().setName("SNYK").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(8.8)
                                .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("SNYK").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(7)
                                .setVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
                                .setScore(8.8))
                        .build()).build();
        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("7.0");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("4.7");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("2.2");
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
    }

    @Test
    void testConvertWithRatingsWithoutVector() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("SNYK-PYTHON-DJANGO-2968205")
                        .setSource(Source.newBuilder().setName("SNYK").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(8.8))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setScore(7)
                                .setVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setMethod(SCORE_METHOD_CVSSV31)
                                .setSource(Source.newBuilder().setName("UNSPECIFIED").build())
                                .setScore(8.8))
                        .build()).build();
        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("7.0");
        assertThat(vuln.getCvssV3ImpactSubScore()).isEqualTo("4.7");
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isEqualTo("2.2");
    }

    @Test
    void testConvertWithNoRatings() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("Foo")
                        .setSource(Source.newBuilder().setName("OSSINDEX").build())
                        .build()).build();
        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2Vector()).isNull();
        assertThat(vuln.getCvssV2BaseScore()).isNull();
        assertThat(vuln.getCvssV2ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isNull();
        assertThat(vuln.getOwaspRRVector()).isNull();
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isNull();
        assertThat(vuln.getOwaspRRLikelihoodScore()).isNull();
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isNull();
    }

    @Test
    void testConvertWithOnlyThirdPartyRatings() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("SONATYPE-001")
                        .setSource(Source.newBuilder().setName("OSSINDEX").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setMethod(SCORE_METHOD_CVSSV2)
                                .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("GITHUB").build())
                                .setMethod(SCORE_METHOD_OWASP)
                                .setVector("SL:1/M:4/O:4/S:9/ED:7/EE:3/A:4/ID:3/LC:9/LI:1/LAV:5/LAC:1/FD:3/RD:4/NC:7/PV:9"))
                        .build()).build();
        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getCvssV3Vector()).isNull();
        assertThat(vuln.getCvssV3BaseScore()).isNull();
        assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNull();
        assertThat(vuln.getCvssV3ImpactSubScore()).isNull();
        assertThat(vuln.getCvssV2Vector()).isEqualTo("(AV:N/AC:M/Au:N/C:C/I:C/A:C)");
        assertThat(vuln.getCvssV2BaseScore()).isEqualTo(BigDecimal.valueOf(9.3));
        assertThat(vuln.getCvssV2ImpactSubScore()).isEqualTo("10.0");
        assertThat(vuln.getCvssV2ExploitabilitySubScore()).isEqualTo("8.6");
        assertThat(vuln.getOwaspRRVector()).isEqualTo("SL:1/M:4/O:4/S:9/ED:7/EE:3/A:4/ID:3/LC:9/LI:1/LAV:5/LAC:1/FD:3/RD:4/NC:7/PV:9");
        assertThat(vuln.getOwaspRRBusinessImpactScore()).isEqualTo("5.75");
        assertThat(vuln.getOwaspRRLikelihoodScore()).isEqualTo("4.375");
        assertThat(vuln.getOwaspRRTechnicalImpactScore()).isEqualTo("4.0");
    }

    @Test
    void testConvertWithRatingWithoutMethod() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("SONATYPE-001")
                        .setSource(Source.newBuilder().setName("OSSINDEX").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("NVD").build())
                                .setVector("(AV:N/AC:M/Au:N/C:C/I:C/A:C)"))
                        .build()).build();
        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
    }

    @Test
    void testConvertRangeToVersList() {
        var range = "vers:earth/<=6.0.7";
        List<Vers> versConverted = BovModelConverter.convertRangeToVersList(range);
        assertThat(versConverted.getFirst().toString()).isEqualTo("vers:earth/<=6.0.7");
    }

    @Test
    public void testConvertWithRatingsWithCvssV4() {
        final Bom bovInput = Bom.newBuilder().addVulnerabilities(
                org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId("SNYK-PYTHON-DJANGO-2968205")
                        .setSource(Source.newBuilder().setName("SNYK").build())
                        .addRatings(VulnerabilityRating.newBuilder()
                                .setSource(Source.newBuilder().setName("SNYK").build())
                                .setMethod(SCORE_METHOD_CVSSV4)
                                .setScore(7)
                                .setVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A"))
                        .build()).build();
        final Vulnerability vuln = BovModelConverter.convert(bovInput, bovInput.getVulnerabilities(0), true);
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("SNYK-PYTHON-DJANGO-2968205");
        assertThat(vuln.getSource()).isEqualTo(Vulnerability.Source.SNYK.name());
        assertThat(vuln.getCvssV4Vector()).isEqualTo("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A");
        assertThat(vuln.getCvssV4Score()).isEqualTo("7.0");
    }

    @Nested
    class ExtractVulnerableSoftwareTest {

        @Test
        void shouldConvertWildcardToStartIncludingZero() {
            final Bom bov = createBovWithVersionRange("vers:npm/*");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isNull();
            });
        }

        @Test
        void shouldConvertSingleEqualsConstraintToExactVersion() {
            final Bom bov = createBovWithVersionRange("vers:npm/1.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isEqualTo("1.0.0");
                assertThat(vs.getVersionStartIncluding()).isNull();
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isNull();
            });
        }

        @Test
        void shouldConvertGreaterThanOrEqualZeroToStartIncludingZero() {
            final Bom bov = createBovWithVersionRange("vers:npm/>=0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isNull();
            });
        }

        @Test
        void shouldConvertGreaterThanZeroToStartExcludingZero() {
            final Bom bov = createBovWithVersionRange("vers:npm/>0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isNull();
                assertThat(vs.getVersionStartExcluding()).isEqualTo("0");
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isNull();
            });
        }

        @Test
        void shouldHandleOpenEndedStartRange() {
            final Bom bov = createBovWithVersionRange("vers:npm/>=1.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("1.0.0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isNull();
            });
        }

        @Test
        void shouldHandleOpenEndedEndRange() {
            final Bom bov = createBovWithVersionRange("vers:npm/<2.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isNull();
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isEqualTo("2.0.0");
            });
        }

        @Test
        void shouldHandleRangeStartingFromZero() {
            final Bom bov = createBovWithVersionRange("vers:npm/>=0|<2.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isEqualTo("2.0.0");
            });
        }

        @Test
        void shouldHandleRangeExcludingZero() {
            final Bom bov = createBovWithVersionRange("vers:npm/>0|<2.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isNull();
                assertThat(vs.getVersionStartExcluding()).isEqualTo("0");
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isEqualTo("2.0.0");
            });
        }

        @Test
        void shouldHandleBoundedRange() {
            final Bom bov = createBovWithVersionRange("vers:npm/>=1.0.0|<2.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("1.0.0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isEqualTo("2.0.0");
            });
        }

        @Test
        void shouldNormalizeZeroZeroZeroToZero() {
            final Bom bov = createBovWithVersionRange("vers:npm/>=0.0.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isNull();
            });
        }

        @Test
        void shouldFallBackToGenericSchemeForInvalidVersion() {
            // "2015.8.0rrc1" is not a valid PEP 440 version, so the pypi scheme will fail.
            // The converter should fall back to the generic scheme.
            final Bom bov = createBovWithVersionRange("vers:pypi/>=2015.8.0rrc1|<2015.8.4");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getVersion()).isNull();
                assertThat(vs.getVersionStartIncluding()).isEqualTo("2015.8.0rrc1");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isEqualTo("2015.8.4");
            });
        }

        @Test
        void shouldProduceTwoEntriesForRangeWithExactVersion() {
            final Bom bov = createBovWithVersionRange("vers:npm/>=1.0.0|<2.0.0|2.5.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactlyInAnyOrder(
                    vs -> {
                        assertThat(vs.getVersion()).isNull();
                        assertThat(vs.getVersionStartIncluding()).isEqualTo("1.0.0");
                        assertThat(vs.getVersionStartExcluding()).isNull();
                        assertThat(vs.getVersionEndIncluding()).isNull();
                        assertThat(vs.getVersionEndExcluding()).isEqualTo("2.0.0");
                    },
                    vs -> {
                        assertThat(vs.getVersion()).isEqualTo("2.5.0");
                        assertThat(vs.getVersionStartIncluding()).isNull();
                        assertThat(vs.getVersionStartExcluding()).isNull();
                        assertThat(vs.getVersionEndIncluding()).isNull();
                        assertThat(vs.getVersionEndExcluding()).isNull();
                    });
        }

        @Test
        void shouldHandleCpeWithVersionRange() {
            final Bom bov = createBovWithCpeAndVersionRange(
                    "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    "vers:generic/>=2.0.0|<2.17.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactly(vs -> {
                assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
                assertThat(vs.getPart()).isEqualTo("a");
                assertThat(vs.getVendor()).isEqualTo("apache");
                assertThat(vs.getProduct()).isEqualTo("log4j");
                assertThat(vs.getVersion()).isEqualTo("*");
                assertThat(vs.getVersionStartIncluding()).isEqualTo("2.0.0");
                assertThat(vs.getVersionStartExcluding()).isNull();
                assertThat(vs.getVersionEndIncluding()).isNull();
                assertThat(vs.getVersionEndExcluding()).isEqualTo("2.17.0");
                assertThat(vs.isVulnerable()).isTrue();
            });
        }

        @Test
        void shouldHandleBothCpeAndPurl() {
            final Bom bov = createBovWithCpePurlAndVersionRange(
                    "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
                    "vers:maven/>=2.0.0|<2.17.0");
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            assertThat(vsList).satisfiesExactlyInAnyOrder(
                    vs -> {
                        assertThat(vs.getCpe23()).isEqualTo("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
                        assertThat(vs.getVendor()).isEqualTo("apache");
                        assertThat(vs.getProduct()).isEqualTo("log4j");
                        assertThat(vs.getVersion()).isEqualTo("*");
                        assertThat(vs.getVersionStartIncluding()).isEqualTo("2.0.0");
                        assertThat(vs.getVersionEndExcluding()).isEqualTo("2.17.0");
                    },
                    vs -> {
                        assertThat(vs.getPurl()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0");
                        assertThat(vs.getPurlType()).isEqualTo("maven");
                        assertThat(vs.getPurlNamespace()).isEqualTo("org.apache.logging.log4j");
                        assertThat(vs.getPurlName()).isEqualTo("log4j-core");
                        assertThat(vs.getPurlVersion()).isEqualTo("2.14.0");
                        assertThat(vs.getVersionStartIncluding()).isEqualTo("2.0.0");
                        assertThat(vs.getVersionEndExcluding()).isEqualTo("2.17.0");
                    });
        }

        private static Bom createBovWithVersionRange(String versionRange) {
            final var component = org.cyclonedx.proto.v1_7.Component.newBuilder()
                    .setBomRef("test-component")
                    .setPurl("pkg:npm/test-package@1.0.0")
                    .build();

            final var vulnAffects = org.cyclonedx.proto.v1_7.VulnerabilityAffects.newBuilder()
                    .setRef("test-component")
                    .addVersions(org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions.newBuilder()
                            .setRange(versionRange)
                            .build())
                    .build();

            final var vuln = org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                    .setId("CVE-2024-0001")
                    .setSource(Source.newBuilder().setName("NVD").build())
                    .addAffects(vulnAffects)
                    .build();

            return Bom.newBuilder()
                    .addComponents(component)
                    .addVulnerabilities(vuln)
                    .build();
        }

        private static Bom createBovWithCpeAndVersionRange(String cpe, String versionRange) {
            final var component = org.cyclonedx.proto.v1_7.Component.newBuilder()
                    .setBomRef("test-component")
                    .setCpe(cpe)
                    .build();

            final var vulnAffects = org.cyclonedx.proto.v1_7.VulnerabilityAffects.newBuilder()
                    .setRef("test-component")
                    .addVersions(org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions.newBuilder()
                            .setRange(versionRange)
                            .build())
                    .build();

            final var vuln = org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                    .setId("CVE-2024-0001")
                    .setSource(Source.newBuilder().setName("NVD").build())
                    .addAffects(vulnAffects)
                    .build();

            return Bom.newBuilder()
                    .addComponents(component)
                    .addVulnerabilities(vuln)
                    .build();
        }

        private static Bom createBovWithCpePurlAndVersionRange(String cpe, String purl, String versionRange) {
            final var component = org.cyclonedx.proto.v1_7.Component.newBuilder()
                    .setBomRef("test-component")
                    .setCpe(cpe)
                    .setPurl(purl)
                    .build();

            final var vulnAffects = org.cyclonedx.proto.v1_7.VulnerabilityAffects.newBuilder()
                    .setRef("test-component")
                    .addVersions(org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions.newBuilder()
                            .setRange(versionRange)
                            .build())
                    .build();

            final var vuln = org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                    .setId("CVE-2024-0001")
                    .setSource(Source.newBuilder().setName("NVD").build())
                    .addAffects(vulnAffects)
                    .build();

            return Bom.newBuilder()
                    .addComponents(component)
                    .addVulnerabilities(vuln)
                    .build();
        }

    }

    @Nested
    class ExtractSourceTest {

        @ParameterizedTest
        @CsvSource({
                "NVD,      NVD",
                "nvd,      NVD",
                "GITHUB,   GITHUB",
                "OSV,      OSV",
                "SNYK,     SNYK",
                "OSSINDEX, OSSINDEX",
                "VULNDB,   VULNDB",
                "INTERNAL, INTERNAL",
                "UNKNOWN,  UNKNOWN"
        })
        void shouldPreferKnownSourceNameOverVulnId(String sourceName, Vulnerability.Source expected) {
            final var source = Source.newBuilder().setName(sourceName).build();
            assertThat(BovModelConverter.extractSource("CVE-2024-1234", source)).isEqualTo(expected);
        }

        @ParameterizedTest
        @CsvSource({
                "CVE-2024-12345,   NVD",
                "cve-2024-12345,   NVD",
                "GHSA-xxxx-yyyy-zzzz, GITHUB",
                "INTERNAL-foo,     INTERNAL",
                "OSV-2024-1,       OSV",
                "SNYK-JS-FOO-123,  SNYK"
        })
        void shouldInferSourceFromVulnIdWhenSourceNameIsUnrecognized(String vulnId, Vulnerability.Source expected) {
            final var source = Source.newBuilder().setName("NOT_A_REAL_SOURCE").build();
            assertThat(BovModelConverter.extractSource(vulnId, source)).isEqualTo(expected);
        }

        @Test
        void shouldInferSourceFromVulnIdWhenSourceNameIsAbsent() {
            final var source = Source.newBuilder().build();
            assertThat(BovModelConverter.extractSource("CVE-2024-1234", source))
                    .isEqualTo(Vulnerability.Source.NVD);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "PYSEC-2024-1",
                "RUSTSEC-2024-0001",
                "GO-2024-0001",
                "MAL-2024-1",
                "RHSA-2024:1234",
                "no-recognizable-prefix",
                "CVE-2024-123",
                ""
        })
        void shouldFallBackToUnknownWhenNeitherSourceNameNorVulnIdMatch(String vulnId) {
            final var source = Source.newBuilder().setName("NOT_A_REAL_SOURCE").build();
            assertThat(BovModelConverter.extractSource(vulnId, source))
                    .isEqualTo(Vulnerability.Source.UNKNOWN);
        }

        @Test
        void shouldFallBackToUnknownWhenBothSourceNameAndVulnIdAreAbsent() {
            final var source = Source.newBuilder().build();
            assertThat(BovModelConverter.extractSource("", source))
                    .isEqualTo(Vulnerability.Source.UNKNOWN);
        }

    }
}