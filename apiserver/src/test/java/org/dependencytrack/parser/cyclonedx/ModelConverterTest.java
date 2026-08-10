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
package org.dependencytrack.parser.cyclonedx;

import org.cyclonedx.model.Hash;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ModelConverterTest extends PersistenceCapableTest {

    @Test
    void shouldSkipFindingWhoseComponentWasDeleted() {
        final Project project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component = qm.createComponent(component, false);
        qm.addVulnerability(vulnerability, component, "internal");

        // Resolve the findings up front, mirroring what the exporter does before conversion.
        final List<Finding> findings = withJdbiHandle(handle ->
                handle.attach(FindingDao.class).getFindings(project.getId(), true));
        assertThat(findings).hasSize(1);

        // Simulate the component being deleted in the window between the findings query
        // and the export (e.g. a concurrent re-analysis or manual deletion).
        final Component deletedComponent = component;
        withJdbiHandle(handle -> handle.attach(ComponentDao.class).deleteComponent(deletedComponent.getUuid()));

        // Before the fix this threw a NullPointerException and aborted the whole export.
        assertThatNoException().isThrownBy(() ->
                ModelConverter.generateVulnerabilities(qm, CycloneDXExporter.Variant.VEX, findings));

        final List<org.cyclonedx.model.vulnerability.Vulnerability> result =
                ModelConverter.generateVulnerabilities(qm, CycloneDXExporter.Variant.VEX, findings);
        assertThat(result).isEmpty();
    }

    @Test
    void shouldConvertFindingWithResolvableComponent() {
        final Project project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component = qm.createComponent(component, false);
        qm.addVulnerability(vulnerability, component, "internal");

        final List<Finding> findings = withJdbiHandle(handle ->
                handle.attach(FindingDao.class).getFindings(project.getId(), true));

        final List<org.cyclonedx.model.vulnerability.Vulnerability> result =
                ModelConverter.generateVulnerabilities(qm, CycloneDXExporter.Variant.VEX, findings);
        assertThat(result).hasSize(1);
        assertThat(result.getFirst().getId()).isEqualTo("INT-001");
    }

    @Nested
    class HashConversionTest {

        @ParameterizedTest
        @MethodSource("hashFixtures")
        void shouldConvertHashFromCdxComponent(HashFixture fixture) {
            final var cdxComponent = new org.cyclonedx.model.Component();
            cdxComponent.setName("acme-lib");
            cdxComponent.addHash(new Hash(fixture.algorithm(), fixture.value()));

            final Component component = ModelConverter.convertComponent(cdxComponent);
            assertThat(fixture.getter().apply(component)).isEqualTo(fixture.value());
        }

        @ParameterizedTest
        @MethodSource("hashFixtures")
        void shouldConvertHashToCdxComponent(HashFixture fixture) {
            final var component = new Component();
            component.setUuid(UUID.randomUUID());
            component.setName("acme-lib");
            fixture.setter().accept(component, fixture.value());

            assertThat(ModelConverter.convert(component).getHashes()).satisfiesExactly(hash -> {
                assertThat(hash.getAlgorithm()).isEqualTo(fixture.algorithm().getSpec());
                assertThat(hash.getValue()).isEqualTo(fixture.value());
            });
        }

        @Test
        void hashFixturesShouldCoverAllAlgorithms() {
            // Make sure we detect when upstream schema adds new hash algos
            // that we don't have coverage for yet.
            assertThat(hashFixtures())
                    .map(HashFixture::algorithm)
                    .containsExactlyInAnyOrder(Hash.Algorithm.values());
        }

        private record HashFixture(
                Hash.Algorithm algorithm,
                String value,
                BiConsumer<Component, String> setter,
                Function<Component, String> getter) {

            @Override
            public @NonNull String toString() {
                return algorithm.name();
            }

        }

        private static List<HashFixture> hashFixtures() {
            return List.of(
                    hashFixture(Hash.Algorithm.MD5, 32, Component::setMd5, Component::getMd5),
                    hashFixture(Hash.Algorithm.SHA1, 40, Component::setSha1, Component::getSha1),
                    hashFixture(Hash.Algorithm.SHA_256, 64, Component::setSha256, Component::getSha256),
                    hashFixture(Hash.Algorithm.SHA_384, 96, Component::setSha384, Component::getSha384),
                    hashFixture(Hash.Algorithm.SHA_512, 128, Component::setSha512, Component::getSha512),
                    hashFixture(Hash.Algorithm.SHA3_256, 64, Component::setSha3_256, Component::getSha3_256),
                    hashFixture(Hash.Algorithm.SHA3_384, 96, Component::setSha3_384, Component::getSha3_384),
                    hashFixture(Hash.Algorithm.SHA3_512, 128, Component::setSha3_512, Component::getSha3_512),
                    hashFixture(Hash.Algorithm.BLAKE2b_256, 64, Component::setBlake2b_256, Component::getBlake2b_256),
                    hashFixture(Hash.Algorithm.BLAKE2b_384, 96, Component::setBlake2b_384, Component::getBlake2b_384),
                    hashFixture(Hash.Algorithm.BLAKE2b_512, 128, Component::setBlake2b_512, Component::getBlake2b_512),
                    hashFixture(Hash.Algorithm.BLAKE3, 64, Component::setBlake3, Component::getBlake3),
                    hashFixture(Hash.Algorithm.STREEBOG_256, 64, Component::setStreebog_256, Component::getStreebog_256),
                    hashFixture(Hash.Algorithm.STREEBOG_512, 128, Component::setStreebog_512, Component::getStreebog_512));
        }

        private static HashFixture hashFixture(
                Hash.Algorithm algorithm,
                int valueLength,
                BiConsumer<Component, String> setter,
                Function<Component, String> getter) {
            return new HashFixture(
                    algorithm,
                    "%02x".formatted(algorithm.ordinal()) + "a".repeat(valueLength - 2),
                    setter,
                    getter);
        }

    }

}
