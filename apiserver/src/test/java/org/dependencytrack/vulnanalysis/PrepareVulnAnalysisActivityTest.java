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
package org.dependencytrack.vulnanalysis;

import alpine.model.IConfigProperty;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisArg;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisRes;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PrepareVulnAnalysisActivityTest extends PersistenceCapableTest {

    private FileStorage fileStorage;
    private PluginManager pluginManager;
    private PrepareVulnAnalysisActivity activity;

    @BeforeEach
    void beforeEach() {
        fileStorage = new MemoryFileStorage();
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void shouldIncludeComponentTypeWhenRequired() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_PURL,
                VulnAnalyzerRequirement.COMPONENT_TYPE));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var libraryComponent = new org.dependencytrack.model.Component();
        libraryComponent.setProject(project);
        libraryComponent.setGroup("com.example");
        libraryComponent.setName("libraryComponent");
        libraryComponent.setVersion("1.0.0");
        libraryComponent.setPurl("pkg:maven/com.example/libraryComponent@1.0.0");
        libraryComponent.setClassifier(Classifier.LIBRARY);
        qm.persist(libraryComponent);

        final var osComponent = new org.dependencytrack.model.Component();
        osComponent.setProject(project);
        osComponent.setName("ubuntu");
        osComponent.setVersion("22.04");
        osComponent.setClassifier(Classifier.OPERATING_SYSTEM);
        qm.persist(osComponent);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());
        assertThat(res.getAnalyzersList()).containsExactly("mock");

        final Bom bom = readBom(res);

        assertThat(bom.getComponentsList()).satisfiesExactlyInAnyOrder(
                component -> {
                    assertThat(component.getType()).isEqualTo(Classification.CLASSIFICATION_LIBRARY);
                    assertThat(component.getPurl()).isEqualTo("pkg:maven/com.example/libraryComponent@1.0.0");
                },
                component -> {
                    assertThat(component.getType()).isEqualTo(Classification.CLASSIFICATION_OPERATING_SYSTEM);
                    assertThat(component.getName()).isEqualTo("ubuntu");
                });
    }

    @Test
    void shouldIncludeComponentPropertiesWhenRequired() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_PURL,
                VulnAnalyzerRequirement.COMPONENT_TYPE,
                VulnAnalyzerRequirement.COMPONENT_PROPERTIES));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("libc6");
        component.setVersion("2.35");
        component.setPurl("pkg:deb/ubuntu/libc6@2.35");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        qm.createComponentProperty(
                component,
                "aquasecurity",
                "trivy:SrcName",
                "glibc",
                IConfigProperty.PropertyType.STRING,
                null);
        qm.createComponentProperty(
                component,
                "aquasecurity",
                "trivy:SrcVersion",
                "2.35",
                IConfigProperty.PropertyType.STRING,
                null);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());

        final Bom bom = readBom(res);

        assertThat(bom.getComponentsList()).satisfiesExactly(bomComponent -> {
            assertThat(bomComponent.getPurl()).isEqualTo("pkg:deb/ubuntu/libc6@2.35");
            assertThat(bomComponent.getType()).isEqualTo(Classification.CLASSIFICATION_LIBRARY);

            assertThat(bomComponent.getPropertiesList()).satisfiesExactlyInAnyOrder(
                    property -> {
                        assertThat(property.getName()).isEqualTo("aquasecurity:trivy:SrcName");
                        assertThat(property.getValue()).isEqualTo("glibc");
                    },
                    property -> {
                        assertThat(property.getName()).isEqualTo("aquasecurity:trivy:SrcVersion");
                        assertThat(property.getValue()).isEqualTo("2.35");
                    });
        });
    }

    @Test
    void shouldHandleComponentPropertyWithNullGroupName() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_PURL,
                VulnAnalyzerRequirement.COMPONENT_PROPERTIES));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/lib@1.0.0");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        qm.createComponentProperty(
                component,
                null,
                "some-property",
                "some-value",
                IConfigProperty.PropertyType.STRING,
                null);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());

        final Bom bom = readBom(res);

        assertThat(bom.getComponentsList()).satisfiesExactly(bomComponent -> {
            assertThat(bomComponent.getPropertiesList()).satisfiesExactlyInAnyOrder(property -> {
                assertThat(property.getName()).isEqualTo("some-property");
                assertThat(property.getValue()).isEqualTo("some-value");
            });
        });
    }

    @Test
    void shouldExcludeComponentPropertiesWhenNotRequired() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/lib@1.0.0");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        qm.createComponentProperty(
                component,
                "aquasecurity",
                "trivy:SrcName",
                "glibc",
                IConfigProperty.PropertyType.STRING,
                null);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());

        final Bom bom = readBom(res);

        assertThat(bom.getComponentsList()).satisfiesExactly(
                bomComponent -> assertThat(bomComponent.getPropertiesList()).isEmpty());


    }

    @Test
    void shouldExcludeComponentTypeWhenNotRequired() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/lib@1.0.0");
        component.setClassifier(Classifier.LIBRARY);
        qm.persist(component);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());

        final Bom bom = readBom(res);
        final Component c = bom.getComponents(0);

        assertThat(c.getType()).isEqualTo(Classification.CLASSIFICATION_NULL);
    }

    @Test
    void shouldAssociatePropertiesWithCorrectComponents() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_PURL,
                VulnAnalyzerRequirement.COMPONENT_TYPE,
                VulnAnalyzerRequirement.COMPONENT_PROPERTIES));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new org.dependencytrack.model.Component();
        componentA.setProject(project);
        componentA.setName("libc6");
        componentA.setVersion("2.35");
        componentA.setPurl("pkg:deb/ubuntu/libc6@2.35");
        componentA.setClassifier(Classifier.LIBRARY);
        qm.persist(componentA);

        final var componentB = new org.dependencytrack.model.Component();
        componentB.setProject(project);
        componentB.setName("libxml2");
        componentB.setVersion("2.9.1");
        componentB.setPurl("pkg:rpm/amazon/libxml2@2.9.1");
        componentB.setClassifier(Classifier.LIBRARY);
        qm.persist(componentB);

        qm.createComponentProperty(
                componentA,
                "aquasecurity",
                "trivy:SrcName",
                "glibc",
                IConfigProperty.PropertyType.STRING,
                null);
        qm.createComponentProperty(
                componentB,
                "aquasecurity",
                "trivy:SrcName",
                "libxml2",
                IConfigProperty.PropertyType.STRING,
                null);
        qm.createComponentProperty(
                componentB,
                "aquasecurity",
                "trivy:PkgType",
                "amazon",
                IConfigProperty.PropertyType.STRING,
                null);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());

        final Bom bom = readBom(res);

        assertThat(bom.getComponentsList()).satisfiesExactlyInAnyOrder(
                component -> {
                    assertThat(component.getName()).isEqualTo("libc6");
                    assertThat(component.getPropertiesList()).satisfiesExactly(property -> {
                        assertThat(property.getName()).isEqualTo("aquasecurity:trivy:SrcName");
                        assertThat(property.getValue()).isEqualTo("glibc");
                    });
                },
                component -> {
                    assertThat(component.getName()).isEqualTo("libxml2");
                    assertThat(component.getPropertiesList()).satisfiesExactlyInAnyOrder(
                            property -> {
                                assertThat(property.getName()).isEqualTo("aquasecurity:trivy:SrcName");
                                assertThat(property.getValue()).isEqualTo("libxml2");
                            },
                            property -> {
                                assertThat(property.getName()).isEqualTo("aquasecurity:trivy:PkgType");
                                assertThat(property.getValue()).isEqualTo("amazon");
                            });
                });
    }

    @Test
    void shouldMarkInternalComponents() throws Exception {
        setupActivityForAnalyzerRequirements(EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_PURL,
                VulnAnalyzerRequirement.COMPONENT_TYPE));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("internal-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/internal-lib@1.0.0");
        component.setClassifier(Classifier.LIBRARY);
        component.setInternal(true);
        qm.persist(component);

        final PrepareVulnAnalysisRes res = activity.execute(
                mockActivityContext(),
                PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(project.getUuid().toString())
                        .build());

        final Bom bom = readBom(res);
        assertThat(bom.getComponentsList()).satisfiesExactly(bomComponent -> {
            assertThat(bomComponent.getPropertiesList()).satisfiesExactly(property -> {
                assertThat(property.getName()).isEqualTo("dependencytrack:internal:is-internal-component");
                assertThat(property.getValue()).isEqualTo("true");
            });
        });
    }

    private void setupActivityForAnalyzerRequirements(EnumSet<VulnAnalyzerRequirement> requirements) {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretName -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(VulnAnalyzer.class));
        pluginManager.loadPlugins(List.of(
                new MockVulnAnalyzerPlugin(bom -> Bom.getDefaultInstance(), requirements)));
        activity = new PrepareVulnAnalysisActivity(fileStorage, pluginManager);
    }

    private static ActivityContext mockActivityContext() {
        final var ctxMock = mock(ActivityContext.class);
        when(ctxMock.workflowRunId()).thenReturn(UUID.randomUUID());
        return ctxMock;
    }

    private Bom readBom(PrepareVulnAnalysisRes res) throws Exception {
        assertThat(res.hasBomFileMetadata()).isTrue();

        try (final var inputStream = fileStorage.get(res.getBomFileMetadata())) {
            return Bom.parseFrom(inputStream);
        }
    }

}
