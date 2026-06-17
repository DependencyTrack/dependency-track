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
package org.dependencytrack.vulndatasource.github;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.protobuf.util.JsonFormat;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_7.Bom;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;

class ModelConverterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .registerModule(new JavaTimeModule());

    @Test
    void shouldConvertAdvisoryToBom() throws IOException {

        //given
        var securityAdvisory = MAPPER.readValue(getClass().getResourceAsStream("/advisory.json"), SecurityAdvisory.class);

        Bom bom = ModelConverter.convert(securityAdvisory, true);

        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "components": [{
                             "bomRef": "9407f313-a355-3a52-a697-ab76c6641d89",
                             "purl": "pkg:nuget/bootstrap"
                           }, {
                             "bomRef": "0e15be9a-cee8-3e0f-b101-6a7aa2d828ba",
                             "purl": "pkg:nuget/bootstrap.sass"
                           }, {
                             "bomRef": "ad335325-578a-334c-88a5-a64caa0c017e",
                             "purl": "pkg:nuget/Bootstrap.Less"
                           }],
                           "externalReferences": [{
                             "url": "https://github.com/advisories/GHSA-fxwm-579q-49qq"
                           }],
                           "vulnerabilities": [{
                             "id": "GHSA-fxwm-579q-49qq",
                             "source": {
                               "name": "GITHUB"
                             },
                             "references": [{
                               "id": "CVE-2019-8331",
                               "source": {
                                 "name": "NVD"
                               }
                             }],
                             "ratings": [{
                               "method": "SCORE_METHOD_OTHER",
                               "severity": "SEVERITY_MEDIUM",
                               "source": {
                                 "name": "GITHUB"
                               }
                             }],
                             "description": "In Bootstrap 4 before 4.3.1 and Bootstrap 3 before 3.4.1, XSS is possible in the tooltip or popover data-template attribute. For more information, see: https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
                             "published": "2019-02-22T20:54:40Z",
                             "updated": "2021-12-03T14:54:43Z",
                             "affects": [{
                               "ref": "9407f313-a355-3a52-a697-ab76c6641d89",
                               "versions": [{
                                 "range": "vers:nuget/>=4.0.0|<4.3.1"
                               }, {
                                 "range": "vers:nuget/>=3.0.0|<3.4.1"
                               }]
                             }, {
                               "ref": "0e15be9a-cee8-3e0f-b101-6a7aa2d828ba",
                               "versions": [{
                                 "range": "vers:nuget/<4.3.1"
                               }]
                             }, {
                               "ref": "ad335325-578a-334c-88a5-a64caa0c017e",
                               "versions": [{
                                 "range": "vers:nuget/>=3.0.0|<3.4.1"
                               }]
                             }],
                             "properties": [{
                               "name": "dependency-track:vuln:title",
                               "value": "Moderate severity vulnerability that affects Bootstrap.Less, bootstrap, and bootstrap.sass"
                             }]
                           }]
                         }
                        """);
    }

    @Test
    void shouldConvertAdvisoryWithCweAndMultipleExternalReferences() throws IOException {

        //given
        var securityAdvisory = MAPPER.readValue(getClass().getResourceAsStream("/advisory-02.json"), SecurityAdvisory.class);

        Bom bom = ModelConverter.convert(securityAdvisory, true);

        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "components": [{
                             "bomRef": "e68e3ec8-35b8-38af-8e7c-f0891e20246b",
                             "purl": "pkg:npm/dojo"
                           }],
                           "externalReferences": [{
                             "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name\\u003dCVE-2015-5654"
                           }, {
                             "url": "https://snyk.io/vuln/SNYK-JS-DOJO-174933"
                           }, {
                             "url": "https://www.npmjs.com/advisories/973"
                           }, {
                             "url": "https://nvd.nist.gov/vuln/detail/CVE-2015-5654"
                           }, {
                             "url": "http://jvn.jp/en/jp/JVN13456571/index.html"
                           }, {
                             "url": "http://jvndb.jvn.jp/jvndb/JVNDB-2015-000153"
                           }, {
                             "url": "http://www-01.ibm.com/support/docview.wss?uid\\u003dswg21975256"
                           }, {
                             "url": "http://www.securityfocus.com/bid/77026"
                           }, {
                             "url": "http://www.securitytracker.com/id/1034848"
                           }, {
                             "url": "https://github.com/advisories/GHSA-p82g-2xpp-m5r3"
                           }],
                           "vulnerabilities": [{
                             "id": "GHSA-p82g-2xpp-m5r3",
                             "source": {
                               "name": "GITHUB"
                             },
                             "references": [{
                               "id": "CVE-2015-5654",
                               "source": {
                                 "name": "NVD"
                               }
                             }],
                             "ratings": [{
                               "method": "SCORE_METHOD_CVSSV31",
                               "score": 5.4,
                               "severity": "SEVERITY_MEDIUM",
                               "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                               "source": {
                                 "name": "GITHUB"
                               }
                             }],
                             "cwes": [79],
                             "description": "Versions of `dojo` prior to 1.2.0 are vulnerable to Cross-Site Scripting (XSS). The package fails to sanitize HTML code in user-controlled input, allowing attackers to execute arbitrary JavaScript in the victim\\u0027s browser.\\n\\n\\n## Recommendation\\n\\nUpgrade to version 1.2.0 or later.",
                             "published": "2020-09-11T21:18:05Z",
                             "updated": "2023-01-06T05:01:55Z",
                             "affects": [{
                               "ref": "e68e3ec8-35b8-38af-8e7c-f0891e20246b",
                               "versions": [{
                                 "range": "vers:npm/<1.2.0"
                               }]
                             }],
                             "properties": [{
                               "name": "dependency-track:vuln:title",
                               "value": "Cross-Site Scripting in dojo"
                             }]
                           }]
                         }
                        """);
    }

    @Test
    public void testAliasSyncDisabled() throws IOException {

        //given
        SecurityAdvisory securityAdvisory = MAPPER.readValue(getClass().getResourceAsStream("/advisory-02.json"), SecurityAdvisory.class);

        Bom bom = ModelConverter.convert(securityAdvisory, false);

        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "components": [{
                             "bomRef": "e68e3ec8-35b8-38af-8e7c-f0891e20246b",
                             "purl": "pkg:npm/dojo"
                           }],
                           "externalReferences": [{
                             "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name\\u003dCVE-2015-5654"
                           }, {
                             "url": "https://snyk.io/vuln/SNYK-JS-DOJO-174933"
                           }, {
                             "url": "https://www.npmjs.com/advisories/973"
                           }, {
                             "url": "https://nvd.nist.gov/vuln/detail/CVE-2015-5654"
                           }, {
                             "url": "http://jvn.jp/en/jp/JVN13456571/index.html"
                           }, {
                             "url": "http://jvndb.jvn.jp/jvndb/JVNDB-2015-000153"
                           }, {
                             "url": "http://www-01.ibm.com/support/docview.wss?uid\\u003dswg21975256"
                           }, {
                             "url": "http://www.securityfocus.com/bid/77026"
                           }, {
                             "url": "http://www.securitytracker.com/id/1034848"
                           }, {
                             "url": "https://github.com/advisories/GHSA-p82g-2xpp-m5r3"
                           }],
                           "vulnerabilities": [{
                             "id": "GHSA-p82g-2xpp-m5r3",
                             "source": {
                               "name": "GITHUB"
                             },
                             "ratings": [{
                               "method": "SCORE_METHOD_CVSSV31",
                               "score": 5.4,
                               "severity": "SEVERITY_MEDIUM",
                               "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                               "source": {
                                 "name": "GITHUB"
                               }
                             }],
                             "cwes": [79],
                             "description": "Versions of `dojo` prior to 1.2.0 are vulnerable to Cross-Site Scripting (XSS). The package fails to sanitize HTML code in user-controlled input, allowing attackers to execute arbitrary JavaScript in the victim\\u0027s browser.\\n\\n\\n## Recommendation\\n\\nUpgrade to version 1.2.0 or later.",
                             "published": "2020-09-11T21:18:05Z",
                             "updated": "2023-01-06T05:01:55Z",
                             "affects": [{
                               "ref": "e68e3ec8-35b8-38af-8e7c-f0891e20246b",
                               "versions": [{
                                 "range": "vers:npm/<1.2.0"
                               }]
                             }],
                             "properties": [{
                               "name": "dependency-track:vuln:title",
                               "value": "Cross-Site Scripting in dojo"
                             }]
                           }]
                         }
                        """);
    }

    @Test
    void shouldConvertCvssV4Rating() throws IOException {

        //given
        var securityAdvisory = MAPPER.readValue(getClass().getResourceAsStream("/advisory-03.json"), SecurityAdvisory.class);

        Bom bom = ModelConverter.convert(securityAdvisory, true);

        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "components": [{
                             "bomRef": "9407f313-a355-3a52-a697-ab76c6641d89",
                             "purl": "pkg:nuget/bootstrap"
                           }],
                           "vulnerabilities": [{
                             "id": "GHSA-fxwm-579q-49qq",
                             "source": {
                               "name": "GITHUB"
                             },
                             "ratings": [{
                               "method": "SCORE_METHOD_CVSSV4",
                               "score": 10.0,
                               "severity": "SEVERITY_CRITICAL",
                               "source": {
                                 "name": "GITHUB"
                               },
                               "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                             }],
                             "description": "In Bootstrap 4 before 4.3.1 and Bootstrap 3 before 3.4.1, XSS is possible in the tooltip or popover data-template attribute. For more information, see: https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
                             "published": "2026-02-22T20:54:40Z",
                             "updated": "2026-12-03T14:54:43Z",
                             "affects": [{
                               "ref": "9407f313-a355-3a52-a697-ab76c6641d89",
                               "versions": [{
                                 "range": "vers:nuget/>=4.0.0|<4.3.1"
                               }]
                             }],
                             "properties": [{
                               "name": "dependency-track:vuln:title",
                               "value": "Critical severity vulnerability that affects Bootstrap.Less, bootstrap, and bootstrap.sass"
                             }]
                           }]
                         }
                        """);
    }

    @Test
    void shouldEmitBothCvssV3AndCvssV4RatingsWhenBothPresent() throws IOException {
        var securityAdvisory = MAPPER.readValue(getClass().getResourceAsStream("/advisory-04.json"), SecurityAdvisory.class);

        Bom bom = ModelConverter.convert(securityAdvisory, true);

        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .inPath("$.vulnerabilities[0].ratings")
                .isEqualTo("""
                        [
                          {
                            "method": "SCORE_METHOD_CVSSV4",
                            "score": 10.0,
                            "severity": "SEVERITY_CRITICAL",
                            "source": { "name": "GITHUB" },
                            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                          },
                          {
                            "method": "SCORE_METHOD_CVSSV31",
                            "score": 9.8,
                            "severity": "SEVERITY_CRITICAL",
                            "source": { "name": "GITHUB" },
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                          }
                        ]
                        """);
    }
}
