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
package org.dependencytrack.persistence.converter;

import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DataClassification;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tools;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class ToolsJsonConverterTest {

    @Test
    public void testConvertToDatastore() {
        final var project = new Project();
        project.setName("acme-app");

        final var componentSupplier = new OrganizationalEntity();
        componentSupplier.setName("componentSupplierName");

        final var externalReference = new ExternalReference();
        externalReference.setType(org.cyclonedx.model.ExternalReference.Type.DOCUMENTATION);
        externalReference.setUrl("https://example.com");

        final var componentAuthor = new OrganizationalContact();
        componentAuthor.setName("componentAuthor");

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);

        final var component = new Component();
        component.setProject(project);
        component.setId(123);
        component.setUuid(UUID.randomUUID());
        component.setAuthors(List.of(componentAuthor));
        component.setPublisher("componentPublisher");
        component.setSupplier(componentSupplier);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setClassifier(Classifier.LIBRARY);
        component.setFilename("componentFilename");
        component.setExtension("componentExtension");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha384("componentSha384");
        component.setSha512("componentSha512");
        component.setSha3_256("componentSha3_256");
        component.setSha3_384("componentSha3_384");
        component.setSha3_512("componentSha3_512");
        component.setBlake2b_256("componentBlake2b_256");
        component.setBlake2b_384("componentBlake2b_384");
        component.setBlake2b_512("componentBlake2b_512");
        component.setBlake3("componentBlake3");
        component.setCpe("componentCpe");
        component.setPurl("pkg:maven/componentGroup/componentName@componentVersion?foo=bar");
        component.setPurlCoordinates("pkg:maven/componentGroup/componentName@componentVersion");
        component.setSwidTagId("componentSwidTagId");
        component.setInternal(true);
        component.setDescription("componentDescription");
        component.setCopyright("componentCopyright");
        component.setLicense("componentLicense");
        component.setLicenseExpression("componentLicenseExpression");
        component.setLicenseUrl("componentLicenseUrl");
        component.setDirectDependencies("componentDirectDependencies");
        component.setExternalReferences(List.of(externalReference));
        component.setParent(component);
        component.setChildren(List.of(component));
        component.setVulnerabilities(List.of(vuln));
        component.setLastInheritedRiskScore(10.0);
        component.setNotes("componentNotes");

        final var serviceProvider = new OrganizationalEntity();
        serviceProvider.setName("serviceProviderName");

        final var serviceDataClassification = new DataClassification();
        serviceDataClassification.setDirection(DataClassification.Direction.OUTBOUND);
        serviceDataClassification.setName("serviceDataClassificationName");

        final var service = new ServiceComponent();
        service.setProject(project);
        service.setId(123);
        service.setUuid(UUID.randomUUID());
        service.setProvider(serviceProvider);
        service.setGroup("serviceGroup");
        service.setName("serviceName");
        service.setVersion("serviceVersion");
        service.setDescription("serviceDescription");
        service.setEndpoints(new String[]{"https://example.com"});
        service.setAuthenticated(true);
        service.setCrossesTrustBoundary(true);
        service.setData(List.of(serviceDataClassification));
        service.setExternalReferences(List.of(externalReference));
        service.setParent(service);
        service.setChildren(List.of(service));
        service.setVulnerabilities(List.of(vuln));
        service.setLastInheritedRiskScore(11.0);
        service.setNotes("serviceNotes");

        assertThatJson(new ToolsJsonConverter().convertToDatastore(new Tools(List.of(component), List.of(service))))
                .isEqualTo("""
                        {
                          "components": [
                            {
                               "authors": [
                                 {
                                   "name": "componentAuthor"
                                 }
                               ],
                               "blake2b_256": "componentBlake2b_256",
                               "blake2b_384": "componentBlake2b_384",
                               "blake2b_512": "componentBlake2b_512",
                               "blake3": "componentBlake3",
                               "classifier": "LIBRARY",
                               "cpe": "componentCpe",
                               "externalReferences": [
                                 {
                                   "type": "documentation",
                                   "url": "https://example.com"
                                 }
                               ],
                               "group": "componentGroup",
                               "md5": "componentmd5",
                               "name": "componentName",
                               "publisher": "componentPublisher",
                               "purl": "pkg:maven/componentGroup/componentName@componentVersion?foo=bar",
                               "sha1": "componentsha1",
                               "sha256": "componentsha256",
                               "sha384": "componentsha384",
                               "sha3_256": "componentsha3_256",
                               "sha3_384": "componentsha3_384",
                               "sha3_512": "componentsha3_512",
                               "sha512": "componentsha512",
                               "supplier": {
                                 "name": "componentSupplierName"
                               },
                               "swidTagId": "componentSwidTagId",
                               "version": "componentVersion"
                             }
                          ],
                          "services": [
                            {
                              "provider": {
                                "name": "serviceProviderName"
                              },
                              "group": "serviceGroup",
                              "name": "serviceName",
                              "version": "serviceVersion",
                              "description": "serviceDescription",
                              "endpoints": [
                                "https://example.com"
                              ],
                              "authenticated": true,
                              "crossesTrustBoundary": true,
                              "data": [
                                {
                                  "direction": "OUTBOUND",
                                  "name": "serviceDataClassificationName"
                                }
                              ],
                              "externalReferences": [
                                {
                                  "type": "documentation",
                                  "url": "https://example.com"
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testConvertToAttribute() {
        final Tools tools = new ToolsJsonConverter().convertToAttribute("""
                {
                  "components": [
                    {
                       "author": "componentAuthor",
                       "authors": [
                         {
                           "name": "componentAuthor"
                         }
                       ],
                       "blake2b_256": "componentBlake2b_256",
                       "blake2b_384": "componentBlake2b_384",
                       "blake2b_512": "componentBlake2b_512",
                       "blake3": "componentBlake3",
                       "classifier": "LIBRARY",
                       "cpe": "componentCpe",
                       "externalReferences": [
                         {
                           "type": "documentation",
                           "url": "https://example.com"
                         }
                       ],
                       "group": "componentGroup",
                       "md5": "componentmd5",
                       "name": "componentName",
                       "publisher": "componentPublisher",
                       "purl": "pkg:maven/componentGroup/componentName@componentVersion?foo=bar",
                       "sha1": "componentsha1",
                       "sha256": "componentsha256",
                       "sha384": "componentsha384",
                       "sha3_256": "componentsha3_256",
                       "sha3_384": "componentsha3_384",
                       "sha3_512": "componentsha3_512",
                       "sha512": "componentsha512",
                       "supplier": {
                         "name": "componentSupplierName"
                       },
                       "swidTagId": "componentSwidTagId",
                       "version": "componentVersion"
                     }
                  ],
                  "services": [
                    {
                      "provider": {
                        "name": "serviceProviderName"
                      },
                      "group": "serviceGroup",
                      "name": "serviceName",
                      "version": "serviceVersion",
                      "description": "serviceDescription",
                      "endpoints": [
                        "https://example.com"
                      ],
                      "authenticated": true,
                      "crossesTrustBoundary": true,
                      "data": [
                        {
                          "direction": "OUTBOUND",
                          "name": "serviceDataClassificationName"
                        }
                      ],
                      "externalReferences": [
                        {
                          "type": "documentation",
                          "url": "https://example.com"
                        }
                      ]
                    }
                  ]
                }
                """);

        assertThat(tools).isNotNull();
        assertThat(tools.components()).satisfiesExactly(component -> {
             assertThat(component.getAuthors().get(0).getName()).isEqualTo("componentAuthor");
             assertThat(component.getAuthors().size()==1);
             assertThat(component.getBlake2b_256()).isEqualTo("componentBlake2b_256");
             assertThat(component.getBlake2b_384()).isEqualTo("componentBlake2b_384");
             assertThat(component.getBlake2b_512()).isEqualTo("componentBlake2b_512");
             assertThat(component.getBlake3()).isEqualTo("componentBlake3");
             assertThat(component.getClassifier()).isEqualTo(Classifier.LIBRARY);
             assertThat(component.getCpe()).isEqualTo("componentCpe");
             assertThat(component.getExternalReferences()).satisfiesExactly(externalReference -> {
                 assertThat(externalReference.getType()).isEqualTo(org.cyclonedx.model.ExternalReference.Type.DOCUMENTATION);
                 assertThat(externalReference.getUrl()).isEqualTo("https://example.com");
             });
             assertThat(component.getGroup()).isEqualTo("componentGroup");
             assertThat(component.getMd5()).isEqualTo("componentmd5");
             assertThat(component.getName()).isEqualTo("componentName");
             assertThat(component.getPublisher()).isEqualTo("componentPublisher");
             assertThat(component.getPurl()).asString().isEqualTo("pkg:maven/componentGroup/componentName@componentVersion?foo=bar");
             assertThat(component.getSha1()).isEqualTo("componentsha1");
             assertThat(component.getSha256()).isEqualTo("componentsha256");
             assertThat(component.getSha384()).isEqualTo("componentsha384");
             assertThat(component.getSha512()).isEqualTo("componentsha512");
             assertThat(component.getSha3_256()).isEqualTo("componentsha3_256");
             assertThat(component.getSha3_384()).isEqualTo("componentsha3_384");
             assertThat(component.getSha3_512()).isEqualTo("componentsha3_512");
             assertThat(component.getSupplier()).satisfies(supplier -> assertThat(supplier.getName()).isEqualTo("componentSupplierName"));
             assertThat(component.getSwidTagId()).isEqualTo("componentSwidTagId");
             assertThat(component.getVersion()).isEqualTo("componentVersion");
        });
        assertThat(tools.services()).satisfiesExactly(service -> {
            assertThat(service.getProvider()).satisfies(provider -> assertThat(provider.getName()).isEqualTo("serviceProviderName"));
            assertThat(service.getGroup()).isEqualTo("serviceGroup");
            assertThat(service.getName()).isEqualTo("serviceName");
            assertThat(service.getVersion()).isEqualTo("serviceVersion");
            assertThat(service.getDescription()).isEqualTo("serviceDescription");
            assertThat(service.getEndpoints()).containsOnly("https://example.com");
            assertThat(service.getAuthenticated()).isTrue();
            assertThat(service.getCrossesTrustBoundary()).isTrue();
            assertThat(service.getData()).satisfiesExactly(classification -> {
                assertThat(classification.getDirection()).isEqualTo(DataClassification.Direction.OUTBOUND);
                assertThat(classification.getName()).isEqualTo("serviceDataClassificationName");
            });
            assertThat(service.getExternalReferences()).satisfiesExactly(externalReference -> {
                assertThat(externalReference.getType()).isEqualTo(org.cyclonedx.model.ExternalReference.Type.DOCUMENTATION);
                assertThat(externalReference.getUrl()).isEqualTo("https://example.com");
            });
        });
    }

    @Test
    public void testConvertToDatastoreNull() {
        assertThat(new ToolsJsonConverter().convertToDatastore(null)).isNull();
    }

    @Test
    public void testConvertToAttributeNull() {
        assertThat(new ToolsJsonConverter().convertToAttribute(null)).isNull();
    }

}