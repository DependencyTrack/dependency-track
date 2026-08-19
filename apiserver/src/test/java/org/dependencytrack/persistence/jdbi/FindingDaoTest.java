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
package org.dependencytrack.persistence.jdbi;

import alpine.persistence.Pagination;
import alpine.resources.AlpineRequest;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class FindingDaoTest extends PersistenceCapableTest {

    @Nested
    class GetAllFindingsTest {

        @Test
        void shouldReportOffsetPlusReturnedItemsWhenSaturatedPageEndsPastThreshold() {
            createFindings(5);

            final Page<FindingDao.FindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(3, 2),
                    handle -> handle.attach(FindingDao.class).getAllFindings(
                            /* filters */ Map.of(),
                            /* showSuppressed */ false,
                            /* showInactive */ false,
                            /* orderBy */ null,
                            /* totalCountThreshold */ 2));

            assertThat(page.items()).hasSize(2);
            assertThat(page.totalCount()).isEqualTo(new TotalCount(5, TotalCount.Type.AT_LEAST));
        }

        @Test
        void shouldNotRaiseLowerBoundTotalCountAboveTrueTotalForEmptyPage() {
            createFindings(5);

            final Page<FindingDao.FindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(10, 5),
                    handle -> handle.attach(FindingDao.class).getAllFindings(
                            /* filters */ Map.of(),
                            /* showSuppressed */ false,
                            /* showInactive */ false,
                            /* orderBy */ null,
                            /* totalCountThreshold */ 2));

            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount()).isEqualTo(new TotalCount(2, TotalCount.Type.AT_LEAST));
        }

        @Test
        void shouldReportExactTotalCountWhenBoundedCountCompletesWithinThreshold() {
            createFindings(3);

            final Page<FindingDao.FindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(0, 3),
                    handle -> handle.attach(FindingDao.class).getAllFindings(
                            /* filters */ Map.of(),
                            /* showSuppressed */ false,
                            /* showInactive */ false,
                            /* orderBy */ null,
                            /* totalCountThreshold */ 100));

            assertThat(page.items()).hasSize(3);
            assertThat(page.totalCount()).isEqualTo(new TotalCount(3, TotalCount.Type.EXACT));
        }

        @Test
        void shouldReportExactTotalCountWhenUnsaturatedPageEndsResultSet() {
            createFindings(5);

            final Page<FindingDao.FindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(3, 10),
                    handle -> handle.attach(FindingDao.class).getAllFindings(
                            /* filters */ Map.of(),
                            /* showSuppressed */ false,
                            /* showInactive */ false,
                            /* orderBy */ null,
                            /* totalCountThreshold */ 2));

            assertThat(page.items()).hasSize(2);
            assertThat(page.totalCount()).isEqualTo(new TotalCount(5, TotalCount.Type.EXACT));
        }

        @Test
        void shouldReportExactTotalCountForEmptyPagePastEndOfResultSet() {
            createFindings(5);

            final Page<FindingDao.FindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(10, 5),
                    handle -> handle.attach(FindingDao.class).getAllFindings(
                            /* filters */ Map.of(),
                            /* showSuppressed */ false,
                            /* showInactive */ false,
                            /* orderBy */ null,
                            /* totalCountThreshold */ null));

            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount()).isEqualTo(new TotalCount(5, TotalCount.Type.EXACT));
        }

    }

    @Nested
    class GetFindingsByProjectTest {

        @Test
        void shouldReportExactTotalCountForEmptyPagePastEndOfResultSet() {
            final Project project = createFindings(5);

            final Page<FindingDao.FindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(10, 5),
                    handle -> handle.attach(FindingDao.class).getFindingsByProject(
                            project.getId(),
                            /* includeSuppressed */ false,
                            /* searchText */ null,
                            /* hasAnalysis */ null,
                            /* source */ null,
                            /* epssFrom */ null,
                            /* epssTo */ null,
                            /* isKev */ null,
                            /* totalCountThreshold */ null));

            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount()).isEqualTo(new TotalCount(5, TotalCount.Type.EXACT));
        }

    }

    @Nested
    class GetGroupedFindingsTest {

        @Test
        void shouldNotReportLowerBoundTotalCountForEmptyPage() {
            createFindings(5);

            final Page<FindingDao.GroupedFindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(10, 5),
                    handle -> handle.attach(FindingDao.class).getGroupedFindings(
                            /* filters */ Map.of(),
                            /* showInactive */ false,
                            /* boundedTotalCount */ true));

            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount()).isEqualTo(new TotalCount(0, TotalCount.Type.AT_LEAST));
        }

        @Test
        void shouldReportExactTotalCountWhenUnsaturatedPageEndsResultSet() {
            createFindings(5);

            final Page<FindingDao.GroupedFindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(3, 10),
                    handle -> handle.attach(FindingDao.class).getGroupedFindings(
                            /* filters */ Map.of(),
                            /* showInactive */ false,
                            /* boundedTotalCount */ true));

            assertThat(page.items()).hasSize(2);
            assertThat(page.totalCount()).isEqualTo(new TotalCount(5, TotalCount.Type.EXACT));
        }

        @Test
        void shouldNotReportExactTotalCountForEmptyPagePastEndOfResultSet() {
            createFindings(5);

            final Page<FindingDao.GroupedFindingRow> page = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(10, 5),
                    handle -> handle.attach(FindingDao.class).getGroupedFindings(
                            /* filters */ Map.of(),
                            /* showInactive */ false,
                            /* boundedTotalCount */ false));

            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount()).isEqualTo(new TotalCount(0, TotalCount.Type.AT_LEAST));
        }

        @Test
        void shouldReturnEachGroupExactlyOnceAcrossPages() {
            createFindings(5);

            final List<String> vulnIds = Stream.of(
                            apiRequestWithOffsetAndLimit(0, 3),
                            apiRequestWithOffsetAndLimit(3, 3))
                    .map(apiRequest -> withJdbiHandle(
                            apiRequest,
                            handle -> handle.attach(FindingDao.class).getGroupedFindings(
                                    /* filters */ Map.of(),
                                    /* showInactive */ false,
                                    /* boundedTotalCount */ true)))
                    .flatMap(page -> page.items().stream())
                    .map(FindingDao.GroupedFindingRow::vulnId)
                    .toList();

            assertThat(vulnIds).containsExactlyInAnyOrder(
                    "Vuln-0", "Vuln-1", "Vuln-2", "Vuln-3", "Vuln-4");
        }

    }

    @Nested
    class SelectAllProjectFindingsTest {

        @Test
        void shouldReturnAllItemsDespitePaginatedApiRequest() {
            final Project project = createFindings(3);

            final List<FindingDao.FindingRow> items = withJdbiHandle(
                    apiRequestWithOffsetAndLimit(0, 1),
                    handle -> handle.attach(FindingDao.class).selectAllProjectFindings(
                            project.getId(),
                            /* includeSuppressed */ false,
                            /* searchText */ null,
                            /* hasAnalysis */ null,
                            /* source */ null,
                            /* epssFrom */ null,
                            /* epssTo */ null,
                            /* isKev */ null));

            assertThat(items).hasSize(3);
        }

    }

    private static AlpineRequest apiRequestWithOffsetAndLimit(int offset, int limit) {
        return new AlpineRequest(
                /* principal */ null,
                new Pagination(Pagination.Strategy.OFFSET, offset, limit),
                /* filter */ null,
                /* orderBy */ null,
                /* orderDirection */ null);
    }

    private Project createFindings(int findingCount) {
        final Project project = qm.createProject(
                "Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < findingCount; i++) {
            final var component = new Component();
            component.setProject(project);
            component.setName("Component " + i);
            component.setVersion("1.0");

            final var vulnerability = new Vulnerability();
            vulnerability.setVulnId("Vuln-" + i);
            vulnerability.setSource(Vulnerability.Source.INTERNAL);
            vulnerability.setSeverity(Severity.HIGH);

            qm.addVulnerability(
                    qm.createVulnerability(vulnerability),
                    qm.createComponent(component, false),
                    "none");
        }

        return project;
    }

}
