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
package org.dependencytrack.vulndatasource.osv;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@WireMockTest
class OsvCompositeVulnDataSourceTest {

    @Test
    void shouldMirrorAllSources() {
        final Bom BOV_A = Bom.newBuilder().addVulnerabilities(Vulnerability.newBuilder()
                .setId("CVE-A").build()).build();

        final Bom BOV_B = Bom.newBuilder().addVulnerabilities(Vulnerability.newBuilder()
                .setId("CVE-B").build()).build();

        final var dataSourceA = mock(OsvVulnDataSource.class);
        doReturn(true, false).when(dataSourceA).hasNext();
        doReturn(BOV_A).when(dataSourceA).next();

        final var dataSourceB = mock(OsvVulnDataSource.class);
        doReturn(true, false).when(dataSourceB).hasNext();
        doReturn(BOV_B).when(dataSourceB).next();

        final var bovs = new ArrayList<Bom>();


        try (var dataSource = new OsvCompositeVulnDataSource(List.of(dataSourceA, dataSourceB))) {
            while (dataSource.hasNext()) {
                final var bov = dataSource.next();
                bovs.add(bov);
                dataSource.markProcessed(bov);
            }
        }

        assertThat(bovs).containsExactly(BOV_A, BOV_B);
        verify(dataSourceA).markProcessed(BOV_A);
        verify(dataSourceB).markProcessed(BOV_B);
        verify(dataSourceA).close();
        verify(dataSourceB).close();
    }

    @Test
    void markProcessedShouldThrowWhenNothingToProcess() {
        final var compositeDataSource = new OsvCompositeVulnDataSource(List.of(mock(OsvVulnDataSource.class)));
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> compositeDataSource.markProcessed(Bom.newBuilder().build()))
                .withMessage("No current data source to mark processed");
    }
}