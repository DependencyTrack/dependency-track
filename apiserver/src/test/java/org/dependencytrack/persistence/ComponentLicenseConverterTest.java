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
package org.dependencytrack.tasks;

import org.cyclonedx.model.License;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.api.v2.model.UpdateComponentLicenseRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.ComponentLicenseConverter;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ComponentLicenseConverterTest extends PersistenceCapableTest {

    @Test
    void shouldCreateComponentLicenseRowsGivenComponentWithResolvedCandidates() {
        final License mit = new License();
        mit.setId("MIT");
        mit.setName("MIT License");
        mit.setUrl("https://opensource.org/license/mit");

        final License apache = new License();
        apache.setId("Apache-2.0");
        apache.setName("Apache License 2.0");
        apache.setUrl("https://www.apache.org/licenses/LICENSE-2.0");

        final Component component = getComponentWithCandidates(mit, apache);
        final long componentId = 123;
        final Map<String, Long> licenseIds = Map.of("MIT", 101L, "Apache-2.0", 102L);

        final List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(component, componentId, licenseIds);

        assertThat(rows)
                .satisfiesExactly(
                        candidate -> {
                            assertThat(candidate.componentId()).isEqualTo(componentId);
                            assertThat(candidate.licenseId()).isEqualTo(101);
                            assertThat(candidate.licenseUrl()).isEqualTo(mit.getUrl());
                            assertThat(candidate.license()).isNull();
                            assertThat(candidate.licenseExpression()).isNull();
                            assertThat(candidate.ordinality()).isEqualTo(1);
                            assertThat(candidate.acknowledgement()).isEqualTo("DECLARED");
                        },
                        candidate -> {
                            assertThat(candidate.componentId()).isEqualTo(componentId);
                            assertThat(candidate.licenseId()).isEqualTo(102);
                            assertThat(candidate.licenseUrl()).isEqualTo(apache.getUrl());
                            assertThat(candidate.license()).isNull();
                            assertThat(candidate.licenseExpression()).isNull();
                            assertThat(candidate.ordinality()).isEqualTo(2);
                            assertThat(candidate.acknowledgement()).isEqualTo("DECLARED");
                        });
    }

    @Test
    void shouldCreateComponentLicenseRowsGivenComponentWithUnresolvedCandidates() {
        final License custom = new License();
        custom.setId("Custom");
        custom.setName("Custom License");
        custom.setUrl("https://www.custom.org/license");

        final Component component = getComponentWithCandidates(custom);
        final long componentId = 123;

        final List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(component, componentId, Map.of());

        assertThat(rows).satisfiesExactly(candidate -> {
            assertThat(candidate.componentId()).isEqualTo(componentId);
            assertThat(candidate.licenseId()).isNull();
            assertThat(candidate.licenseUrl()).isEqualTo(custom.getUrl());
            assertThat(candidate.license()).isEqualTo(custom.getName());
            assertThat(candidate.licenseExpression()).isNull();
            assertThat(candidate.ordinality()).isEqualTo(1);
            assertThat(candidate.acknowledgement()).isEqualTo("DECLARED");
        });
    }

    @Test
    void shouldCreateComponentLicenseRowGivenComponentWithExpression() {
        final Component component = getComponentWithCandidates();
        component.setLicenseExpression("MIT");
        final long componentId = 123;

        final List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(component, componentId, Map.of());

        assertThat(rows).satisfiesExactly(candidate -> {
            assertThat(candidate.componentId()).isEqualTo(componentId);
            assertThat(candidate.licenseId()).isNull();
            assertThat(candidate.licenseUrl()).isNull();
            assertThat(candidate.license()).isNull();
            assertThat(candidate.licenseExpression()).isEqualTo("MIT");
            assertThat(candidate.ordinality()).isEqualTo(1);
            assertThat(candidate.acknowledgement()).isEqualTo("DECLARED");
        });
    }

    @Test
    void shouldDeduplicateCandidatesGivenComponent() {
        final License mit = new License();
        mit.setId("MIT");
        mit.setName("MIT License");
        mit.setUrl("https://opensource.org/license/mit");

        final License mit2 = new License();
        mit2.setId("MIT");
        mit2.setName("MIT License");
        mit2.setUrl("https://opensource.org/license/mit");

        final Component component = getComponentWithCandidates(mit, mit2);
        final long componentId = 123;
        final Map<String, Long> licenseIds = Map.of("MIT", 101L);

        List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(component, componentId, licenseIds);

        assertThat(rows).satisfiesExactly(candidate -> {
            assertThat(candidate.componentId()).isEqualTo(componentId);
            assertThat(candidate.licenseId()).isEqualTo(101);
            assertThat(candidate.licenseUrl()).isEqualTo(mit.getUrl());
            assertThat(candidate.license()).isNull();
            assertThat(candidate.licenseExpression()).isNull();
            assertThat(candidate.ordinality()).isEqualTo(1);
            assertThat(candidate.acknowledgement()).isEqualTo("DECLARED");
        });
    }

    @Test
    void shouldNotCreateComponentLicenseRowsGivenComponentWithNoCandidates() {
        List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(new Component(), 123L, Map.of());

        assertThat(rows).isEmpty();
    }

    @Test
    void shouldCreateComponentLicenseRowsGivenRequestWithResolvedCandidates() {
        final UpdateComponentLicenseRequest mit = new UpdateComponentLicenseRequest();
        mit.setLicense("MIT");
        mit.setLicenseUrl("https://opensource.org/license/mit");
        mit.setAcknowledgement(UpdateComponentLicenseRequest.AcknowledgementEnum.DECLARED);

        final UpdateComponentLicenseRequest apache = new UpdateComponentLicenseRequest();
        apache.setLicense("Apache-2.0");
        apache.setLicenseUrl("https://www.apache.org/licenses/LICENSE-2.0");
        apache.setAcknowledgement(UpdateComponentLicenseRequest.AcknowledgementEnum.DECLARED);

        final long componentId = 123L;
        final Map<String, Long> licenseIdsByIdentifier = Map.of("MIT", 101L, "Apache-2.0", 102L);

        final List<ComponentDao.ComponentLicenseRow> rows = ComponentLicenseConverter.buildComponentLicenseRows(
                componentId, List.of(mit, apache), licenseIdsByIdentifier);

        assertThat(rows)
                .satisfiesExactly(
                        row -> {
                            assertThat(row.componentId()).isEqualTo(componentId);
                            assertThat(row.licenseId()).isEqualTo(101L);
                            assertThat(row.license()).isNull();
                            assertThat(row.licenseExpression()).isNull();
                            assertThat(row.licenseUrl()).isEqualTo("https://opensource.org/license/mit");
                            assertThat(row.ordinality()).isEqualTo(1);
                            assertThat(row.acknowledgement()).isEqualTo("DECLARED");
                        },
                        row -> {
                            assertThat(row.componentId()).isEqualTo(componentId);
                            assertThat(row.licenseId()).isEqualTo(102L);
                            assertThat(row.license()).isNull();
                            assertThat(row.licenseExpression()).isNull();
                            assertThat(row.licenseUrl()).isEqualTo("https://www.apache.org/licenses/LICENSE-2.0");
                            assertThat(row.ordinality()).isEqualTo(2);
                            assertThat(row.acknowledgement()).isEqualTo("DECLARED");
                        });
    }

    @Test
    void shouldCreateComponentLicenseRowsGivenRequestWithUnresolvedCandidates() {
        final UpdateComponentLicenseRequest custom = new UpdateComponentLicenseRequest();
        custom.setLicense("Custom");
        custom.setLicenseUrl("https://www.custom.org/license");
        custom.setAcknowledgement(UpdateComponentLicenseRequest.AcknowledgementEnum.DECLARED);

        final long componentId = 123L;

        final List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(componentId, List.of(custom), Map.of());

        assertThat(rows).satisfiesExactly(row -> {
            assertThat(row.componentId()).isEqualTo(componentId);
            assertThat(row.licenseId()).isNull();
            assertThat(row.license()).isEqualTo("Custom");
            assertThat(row.licenseExpression()).isNull();
            assertThat(row.licenseUrl()).isEqualTo("https://www.custom.org/license");
            assertThat(row.ordinality()).isEqualTo(1);
            assertThat(row.acknowledgement()).isEqualTo("DECLARED");
        });
    }

    @Test
    void shouldCreateComponentLicenseRowGivenRequestWithExpression() {
        final UpdateComponentLicenseRequest expression = new UpdateComponentLicenseRequest();
        expression.setLicenseExpression("MIT");
        expression.setAcknowledgement(UpdateComponentLicenseRequest.AcknowledgementEnum.DECLARED);

        final long componentId = 123L;

        final List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(componentId, List.of(expression), Map.of());

        assertThat(rows).satisfiesExactly(row -> {
            assertThat(row.componentId()).isEqualTo(componentId);
            assertThat(row.licenseId()).isNull();
            assertThat(row.license()).isNull();
            assertThat(row.licenseExpression()).isEqualTo("MIT");
            assertThat(row.licenseUrl()).isNull();
            assertThat(row.ordinality()).isEqualTo(1);
            assertThat(row.acknowledgement()).isEqualTo("DECLARED");
        });
    }

    @Test
    void shouldDeduplicateCandidatesGivenRequest() {
        final UpdateComponentLicenseRequest mit = new UpdateComponentLicenseRequest();
        mit.setLicense("MIT");
        mit.setLicenseUrl("https://opensource.org/license/mit");
        mit.setAcknowledgement(UpdateComponentLicenseRequest.AcknowledgementEnum.DECLARED);

        final UpdateComponentLicenseRequest mit2 = new UpdateComponentLicenseRequest();
        mit2.setLicense("MIT");
        mit2.setLicenseUrl("https://opensource.org/license/mit");
        mit2.setAcknowledgement(UpdateComponentLicenseRequest.AcknowledgementEnum.DECLARED);

        final long componentId = 123L;
        final Map<String, Long> licenseIdsByIdentifier = Map.of("MIT", 101L);

        final List<ComponentDao.ComponentLicenseRow> rows = ComponentLicenseConverter.buildComponentLicenseRows(
                componentId, List.of(mit, mit2), licenseIdsByIdentifier);

        assertThat(rows).satisfiesExactly(row -> {
            assertThat(row.componentId()).isEqualTo(componentId);
            assertThat(row.licenseId()).isEqualTo(101L);
            assertThat(row.license()).isNull();
            assertThat(row.licenseExpression()).isNull();
            assertThat(row.licenseUrl()).isEqualTo("https://opensource.org/license/mit");
            assertThat(row.ordinality()).isEqualTo(1);
            assertThat(row.acknowledgement()).isEqualTo("DECLARED");
        });
    }

    @Test
    void shouldNotCreateComponentLicenseRowsGivenRequestWithNoCandidates() {
        final List<ComponentDao.ComponentLicenseRow> rows =
                ComponentLicenseConverter.buildComponentLicenseRows(123L, List.of(), Map.of());
        assertThat(rows).isEmpty();
    }

    private Component getComponentWithCandidates(License... licenses) {
        final var component = new Component();
        component.setLicenseCandidates(List.of(licenses));
        return component;
    }
}
