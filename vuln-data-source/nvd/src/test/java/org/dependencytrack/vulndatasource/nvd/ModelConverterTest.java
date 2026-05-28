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
package org.dependencytrack.vulndatasource.nvd;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.protobuf.util.JsonFormat;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

class ModelConverterTest {

    @Test
    public void testVulnerabilityConversion() throws IOException {

        String jsonFile = "src/test/resources/cve-vuln.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(jsonString, DefCveItem.class);

        Bom bov = ModelConverter.convert(cveItem);

        assertThatJson(JsonFormat.printer().print(bov))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "bomRef": "7876921d-3df8-3c87-bcdf-66579b0c4860",
                              "cpe": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                              "name": "linux_kernel",
                              "publisher": "linux",
                              "type": "CLASSIFICATION_OPERATING_SYSTEM"
                            },
                            {
                              "bomRef": "e3e3aa1a-542e-3dee-a577-d4dbe0314003",
                              "cpe": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                              "name": "linux_kernel",
                              "publisher": "linux",
                              "type": "CLASSIFICATION_OPERATING_SYSTEM"
                            }
                          ],
                          "externalReferences": [
                            {
                              "url": "http://marc.info/?l\\u003dbugtraq\\u0026m\\u003d94061108411308\\u0026w\\u003d2"
                            },
                            {
                              "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/7858"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "affects": [
                                {
                                  "ref": "7876921d-3df8-3c87-bcdf-66579b0c4860",
                                  "versions": [
                                    {
                                      "version": "-"
                                    }
                                  ]
                                },
                                {
                                  "ref": "e3e3aa1a-542e-3dee-a577-d4dbe0314003",
                                  "versions": [
                                    {
                                      "range": "vers:generic/>=2.2.0|<=2.2.13"
                                    },
                                    {
                                      "range": "vers:generic/>2.3.0|<2.3.18"
                                    }
                                  ]
                                }
                              ],
                              "cwes": [
                                777
                              ],
                              "description": "Linux kernel before 2.3.18 or 2.2.13pre15, with SLIP and PPP options, allows local unprivileged users to forge IP packets via the TIOCSETD option on tty devices.",
                              "id": "CVE-1999-1341",
                              "published": "1999-10-22T04:00:00Z",
                              "ratings": [
                                {
                                  "method": "SCORE_METHOD_CVSSV2",
                                  "score": 4.6,
                                  "severity": "SEVERITY_MEDIUM",
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P"
                                }
                              ],
                              "source": {
                                "name": "NVD"
                              },
                              "updated": "2018-09-11T14:32:55Z"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testVulnerabilityConversionWithNoRanges() throws IOException {
        String jsonFile = "src/test/resources/cve.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(jsonString, DefCveItem.class);

        Bom bov = ModelConverter.convert(cveItem);
        assertThatJson(JsonFormat.printer().print(bov))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "f486fee5-9fe2-32dd-be48-0d9653a0ff93",
                              "publisher": "thinkcmf",
                              "name": "thinkcmf",
                              "cpe": "cpe:2.3:a:thinkcmf:thinkcmf:6.0.7:*:*:*:*:*:*:*"
                            }
                          ],
                          "externalReferences": [
                            {
                              "url": "https://github.com/thinkcmf/thinkcmf/issues/736"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "CVE-2022-40489",
                              "source": {
                                "name": "NVD"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 8.8,
                                  "severity": "SEVERITY_HIGH",
                                  "method": "SCORE_METHOD_CVSSV31",
                                  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                                }
                              ],
                              "cwes": [
                                352
                              ],
                              "description": "ThinkCMF version 6.0.7 is affected by a Cross Site Request Forgery (CSRF) vulnerability that allows a Super Administrator user to be injected into administrative users.",
                              "published": "2022-12-01T05:15:11Z",
                              "updated": "2022-12-02T17:17:02Z",
                              "affects": [
                                {
                                  "ref": "f486fee5-9fe2-32dd-be48-0d9653a0ff93",
                                  "versions": [
                                    {
                                      "version": "6.0.7"
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testConversionWithDuplicateExactVersionMatches() throws Exception {
        final byte[] cveBytes = Files.readAllBytes(Path.of(getClass().getClassLoader().getResource(
                "CVE-2021-0002-duplicate-exact-version-matches.json").toURI()));
        final DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(cveBytes, DefCveItem.class);

        final Bom bov = ModelConverter.convert(cveItem);
        assertThatJson(JsonFormat.printer().print(bov))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "type": "CLASSIFICATION_OPERATING_SYSTEM",
                              "bomRef": "6bfbc8f0-2f76-32de-8a87-c801d657c29a",
                              "publisher": "fedoraproject",
                              "name": "fedora",
                              "cpe": "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_OPERATING_SYSTEM",
                              "bomRef": "87d98dba-118c-3bc7-ae70-d9c9b7e6dcaa",
                              "publisher": "fedoraproject",
                              "name": "fedora",
                              "cpe": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_OPERATING_SYSTEM",
                              "bomRef": "98b2e632-36b3-3187-a8e9-374e3c6389c1",
                              "publisher": "fedoraproject",
                              "name": "fedora",
                              "cpe": "cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_OPERATING_SYSTEM",
                              "bomRef": "ff01dc6e-a3dd-37c1-9c57-1975b28d225c",
                              "publisher": "intel",
                              "name": "ethernet_controller_e810_firmware",
                              "cpe": "cpe:2.3:o:intel:ethernet_controller_e810_firmware:*:*:*:*:*:linux:*:*"
                            }
                          ],
                          "externalReferences": [
                            {
                              "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EUZYFCI7N4TFZSIGA7WGZ4Q7V3EK76GH/"
                            },
                            {
                              "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LKMUMLUH6ENNMLGTJ5AFRF6764ILEMYJ/"
                            },
                            {
                              "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFLYHRQPDF6ZMESCI3HRNOP6D6GELPFR/"
                            },
                            {
                              "url": "https://security.netapp.com/advisory/ntap-20210827-0008/"
                            },
                            {
                              "url": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00515.html"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "CVE-2021-0002",
                              "source": {
                                "name": "NVD"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 3.6,
                                  "severity": "SEVERITY_LOW",
                                  "method": "SCORE_METHOD_CVSSV2",
                                  "vector": "AV:L/AC:L/Au:N/C:P/I:N/A:P"
                                },
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 7.1,
                                  "severity": "SEVERITY_HIGH",
                                  "method": "SCORE_METHOD_CVSSV31",
                                  "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H"
                                }
                              ],
                              "cwes": [
                                754
                              ],
                              "description": "Improper conditions check in some Intel(R) Ethernet Controllers 800 series Linux drivers before version 1.4.11 may allow an authenticated user to potentially enable information disclosure or denial of service via local access.",
                              "published": "2021-08-11T13:15:15Z",
                              "updated": "2021-11-30T19:43:59Z",
                              "affects": [
                                {
                                  "ref": "6bfbc8f0-2f76-32de-8a87-c801d657c29a",
                                  "versions": [
                                    {
                                      "version": "33"
                                    }
                                  ]
                                },
                                {
                                  "ref": "87d98dba-118c-3bc7-ae70-d9c9b7e6dcaa",
                                  "versions": [
                                    {
                                      "version": "34"
                                    }
                                  ]
                                },
                                {
                                  "ref": "98b2e632-36b3-3187-a8e9-374e3c6389c1",
                                  "versions": [
                                    {
                                      "version": "35"
                                    }
                                  ]
                                },
                                {
                                  "ref": "ff01dc6e-a3dd-37c1-9c57-1975b28d225c",
                                  "versions": [
                                    {
                                      "range": "vers:generic/<1.4.11"
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testConversionWithWildcardVersions() throws Exception {
        final byte[] cveBytes = Files.readAllBytes(Path.of(getClass().getClassLoader().getResource(
                "CVE-2022-31022-all-versions-vulnerable.json").toURI()));
        final DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(cveBytes, DefCveItem.class);

        final Bom bov = ModelConverter.convert(cveItem);
        assertThatJson(JsonFormat.printer().print(bov))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "01c1a457-fde2-3685-afcb-d326034f9e9e",
                              "publisher": "couchbase",
                              "name": "bleve",
                              "cpe": "cpe:2.3:a:couchbase:bleve:*:*:*:*:*:*:*:*"
                            }
                          ],
                          "externalReferences": [
                            {
                              "url": "https://github.com/blevesearch/bleve/commit/1c7509d6a17d36f265c90b4e8f4e3a3182fe79ff"
                            },
                            {
                              "url": "https://github.com/blevesearch/bleve/security/advisories/GHSA-9w9f-6mg8-jp7w"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "CVE-2022-31022",
                              "source": {
                                "name": "NVD"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 2.1,
                                  "severity": "SEVERITY_LOW",
                                  "method": "SCORE_METHOD_CVSSV2",
                                  "vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N"
                                },
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 5.5,
                                  "severity": "SEVERITY_MEDIUM",
                                  "method": "SCORE_METHOD_CVSSV31",
                                  "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"
                                },
                                {
                                  "source": {
                                    "name": "GITHUB"
                                  },
                                  "score": 6.2,
                                  "severity": "SEVERITY_MEDIUM",
                                  "method": "SCORE_METHOD_CVSSV31",
                                  "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
                                }
                              ],
                              "cwes": [
                                288,
                                306
                              ],
                              "description": "Bleve is a text indexing library for go. Bleve includes HTTP utilities under bleve/http package, that are used by its sample application. These HTTP methods pave way for exploitation of a node’s filesystem where the bleve index resides, if the user has used bleve’s own HTTP (bleve/http) handlers for exposing the access to the indexes. For instance, the CreateIndexHandler (`http/index_create.go`) and DeleteIndexHandler (`http/index_delete.go`) enable an attacker to create a bleve index (directory structure) anywhere where the user running the server has the write permissions and to delete recursively any directory owned by the same user account. Users who have used the bleve/http package for exposing access to bleve index without the explicit handling for the Role Based Access Controls(RBAC) of the index assets would be impacted by this issue. There is no patch for this issue because the http package is purely intended to be used for demonstration purposes. Bleve was never designed handle the RBACs, nor it was ever advertised to be used in that way. The collaborators of this project have decided to stay away from adding any authentication or authorization to bleve project at the moment. The bleve/http package is mainly for demonstration purposes and it lacks exhaustive validation of the user inputs as well as any authentication and authorization measures. It is recommended to not use bleve/http in production use cases.",
                              "published": "2022-06-01T20:15:08Z",
                              "updated": "2022-06-09T14:13:24Z",
                              "affects": [
                                {
                                  "ref": "01c1a457-fde2-3685-afcb-d326034f9e9e",
                                  "versions": [
                                    {
                                      "range": "vers:generic/*"
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testConversionWithCvssV3Rating() throws Exception {
        final byte[] cveBytes = Files.readAllBytes(Path.of(getClass().getClassLoader().getResource(
                "CVE-2017-5638-cvssv3-rating.json").toURI()));
        final DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(cveBytes, DefCveItem.class);

        final Bom bov = ModelConverter.convert(cveItem);
        assertThatJson(JsonFormat.printer().print(bov))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "75ac6763-42e2-39f2-838a-eb3e00504078",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.5.1:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "9089ce23-523f-3fdf-95e9-2df36449b2a3",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.3.6:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "bfc945db-1092-3bf0-b1fc-4e27662cb680",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "d2244973-f448-32a0-8e82-5725aaef62b5",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.5:*:*:*:*:*:*:*"
                            }
                          ],
                          "externalReferences": [
                            {
                              "url": "http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "CVE-2017-5638",
                              "source": {
                                "name": "NVD"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 10.0,
                                  "severity": "SEVERITY_HIGH",
                                  "method": "SCORE_METHOD_CVSSV2",
                                  "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
                                },
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 10.0,
                                  "severity": "SEVERITY_CRITICAL",
                                  "method": "SCORE_METHOD_CVSSV3",
                                  "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                }
                              ],
                              "cwes": [
                                20
                              ],
                              "description": "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.",
                              "published": "2017-03-11T02:59:00Z",
                              "updated": "2021-02-24T12:15:16Z",
                              "affects": [
                                {
                                  "ref": "75ac6763-42e2-39f2-838a-eb3e00504078",
                                  "versions": [
                                    {
                                      "version": "2.5.1"
                                    }
                                  ]
                                },
                                {
                                  "ref": "9089ce23-523f-3fdf-95e9-2df36449b2a3",
                                  "versions": [
                                    {
                                      "version": "2.3.6"
                                    }
                                  ]
                                },
                                {
                                  "ref": "bfc945db-1092-3bf0-b1fc-4e27662cb680",
                                  "versions": [
                                    {
                                      "version": "2.3.5"
                                    }
                                  ]
                                },
                                {
                                  "ref": "d2244973-f448-32a0-8e82-5725aaef62b5",
                                  "versions": [
                                    {
                                      "version": "2.5"
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testConversionWithCvssV4Rating() throws Exception {
        final byte[] cveBytes = Files.readAllBytes(Path.of(getClass().getClassLoader().getResource(
                "CVE-2017-5638-cvssv4-rating.json").toURI()));
        final DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(cveBytes, DefCveItem.class);

        final Bom bov = ModelConverter.convert(cveItem);
        assertThatJson(JsonFormat.printer().print(bov))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": [
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "75ac6763-42e2-39f2-838a-eb3e00504078",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.5.1:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "9089ce23-523f-3fdf-95e9-2df36449b2a3",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.3.6:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "bfc945db-1092-3bf0-b1fc-4e27662cb680",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*"
                            },
                            {
                              "type": "CLASSIFICATION_APPLICATION",
                              "bomRef": "d2244973-f448-32a0-8e82-5725aaef62b5",
                              "publisher": "apache",
                              "name": "struts",
                              "cpe": "cpe:2.3:a:apache:struts:2.5:*:*:*:*:*:*:*"
                            }
                          ],
                          "externalReferences": [
                            {
                              "url": "http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "CVE-2017-5638",
                              "source": {
                                "name": "NVD"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "NVD"
                                  },
                                  "score": 10.0,
                                  "severity": "SEVERITY_CRITICAL",
                                  "method": "SCORE_METHOD_CVSSV4",
                                  "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                                }
                              ],
                              "cwes": [
                                20
                              ],
                              "description": "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.",
                              "published": "2017-03-11T02:59:00Z",
                              "updated": "2021-02-24T12:15:16Z",
                              "affects": [
                                {
                                  "ref": "75ac6763-42e2-39f2-838a-eb3e00504078",
                                  "versions": [
                                    {
                                      "version": "2.5.1"
                                    }
                                  ]
                                },
                                {
                                  "ref": "9089ce23-523f-3fdf-95e9-2df36449b2a3",
                                  "versions": [
                                    {
                                      "version": "2.3.6"
                                    }
                                  ]
                                },
                                {
                                  "ref": "bfc945db-1092-3bf0-b1fc-4e27662cb680",
                                  "versions": [
                                    {
                                      "version": "2.3.5"
                                    }
                                  ]
                                },
                                {
                                  "ref": "d2244973-f448-32a0-8e82-5725aaef62b5",
                                  "versions": [
                                    {
                                      "version": "2.5"
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testConversionWithIgnoringAmbiguousRunningOnCpeMatchesAlt() throws Exception {
        final byte[] cveBytes = Files.readAllBytes(Path.of(getClass().getClassLoader().getResource(
                "cve-2024-23113.json").toURI()));
        final DefCveItem cveItem = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .registerModule(new JavaTimeModule()).readValue(cveBytes, DefCveItem.class);

        final Bom bov = ModelConverter.convert(cveItem);

        final var components = bov.getComponentsList();
        assertThat(components).isNotNull();
        assertThat(components).extracting(Component::getCpe).containsExactlyInAnyOrder(
                "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortipam:*:*:*:*:*:*:*:*",
                "cpe:2.3:o:fortinet:fortipam:1.2.0:*:*:*:*:*:*:*"
        );
    }
}

