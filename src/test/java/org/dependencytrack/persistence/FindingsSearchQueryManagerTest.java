package org.dependencytrack.persistence;

import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.persistence.Pagination;
import alpine.resources.AlpineRequest;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class FindingsSearchQueryManagerTest extends PersistenceCapableTest {

    public FindingsSearchQueryManagerTest() {

        // Using a constructor rather than a @BeforeEach setup() method as it seems to be faster - tests run in 50ms
        // using a constructor versus 3000ms using an annotated setup method. End result is identical in both cases.
        super();

        AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
        Mockito.when(alpineRequest.getPagination()).thenReturn(new Pagination(Pagination.Strategy.OFFSET, 0, 25));
        this.qm = new QueryManager(alpineRequest);

        buildAndPersistTestVulnerability("INT-2025-00001", Severity.UNASSIGNED);
        buildAndPersistTestVulnerability("INT-2025-00002", Severity.CRITICAL);
        buildAndPersistTestVulnerability("INT-2025-00003", Severity.MEDIUM);
        buildAndPersistTestVulnerability("INT-2025-00004", Severity.MEDIUM);
        buildAndPersistTestVulnerability("INT-2025-00005", Severity.LOW);

        buildTestProject("Test Project 1 - Active", false, true);
        buildTestProject("Test Project 2 - Active - No Suppression", true, true);
        buildTestProject("Test Project 3 - Inactive - No Suppression", false, false);
        buildTestProject("Test Project 4 - Inactive", true, false);

        for (var projectNum = 5; projectNum <= 10; projectNum++) {
            buildTestProject("Test Project " + projectNum + " - Active", true, true);
        }

    }


    private void buildAndPersistTestVulnerability(String vulnId, Severity severity) {
        var vuln = new Vulnerability();
        vuln.setVulnId(vulnId);
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(severity);
        qm.persist(vuln);
    }


    private Project buildTestProject(final String testProjectName, final boolean suppressFinding, final boolean isActive) {
        var project = qm.createProject(testProjectName, "Description 1", "1.0", null, null, null, isActive, false);

        var comp1 = new Component();
        comp1.setName("Component 1");
        comp1.setProject(project);
        comp1.setVersion("1.0");
        qm.createComponent(comp1, false);

        var vuln11 = qm.getVulnerabilityByVulnId(Vulnerability.Source.INTERNAL, "INT-2025-00001");
        qm.addVulnerability(vuln11, comp1, AnalyzerIdentity.INTERNAL_ANALYZER, "Test Vulnerability 1 on Project " + project.getId(), "https://test.com/INT-2025-00001", new Date(1754397285));
        if (suppressFinding) {
            qm.makeAnalysis(comp1, vuln11, AnalysisState.NOT_AFFECTED, null, AnalysisResponse.UPDATE, null, true);
        }

        var vuln12 = qm.getVulnerabilityByVulnId(Vulnerability.Source.INTERNAL, "INT-2025-00002");
        qm.addVulnerability(vuln12, comp1, AnalyzerIdentity.INTERNAL_ANALYZER, "Test Vulnerability 2 on Project " + project.getId(), "https://test.com/INT-2025-00002", new Date(1754397285));

        var vuln13 = qm.getVulnerabilityByVulnId(Vulnerability.Source.INTERNAL, "INT-2025-00003");
        qm.addVulnerability(vuln13, comp1, AnalyzerIdentity.INTERNAL_ANALYZER, "Test Vulnerability 3 on Project " + project.getId(), "https://test.com/INT-2025-00005", new Date(1754397285));

        var comp2 = new Component();
        comp2.setName("Component 2");
        comp2.setProject(project);
        comp2.setVersion("1.0");
        qm.createComponent(comp2, false);

        // Apply INT-2025-00002 to both components - total number of affected projects should be unaffected
        var vuln22 = qm.getVulnerabilityByVulnId(Vulnerability.Source.INTERNAL, "INT-2025-00002");
        qm.addVulnerability(vuln22, comp2, AnalyzerIdentity.INTERNAL_ANALYZER, "Test Vulnerability 2 on Project " + project.getId(), "https://test.com/INT-2025-00002", new Date(1754397285));

        var vuln24 = qm.getVulnerabilityByVulnId(Vulnerability.Source.INTERNAL, "INT-2025-00004");
        qm.addVulnerability(vuln24, comp2, AnalyzerIdentity.INTERNAL_ANALYZER, "Test Vulnerability 5 on Project " + project.getId(), "https://test.com/INT-2025-00004", new Date(1754397285));

        // Test our setup logic - we should have 5 findings on the project overall including suppressions
        assertEquals(5, qm.getFindings(project, true).size(), "Total number of findings including suppressions is wrong");
        assertEquals(suppressFinding ? 4 : 5, qm.getFindings(project, false).size(), "Total number of findings excluding suppressions is wrong");

        return project;
    }


    private Matcher<GroupedFinding> hasVulnerabilityWith(String expectedVulnId, Long expectedProjectCount) {
        return allOf(
                hasProperty("vulnerability", hasEntry("vulnId", expectedVulnId)),
                hasProperty("vulnerability", hasEntry("affectedProjectCount", expectedProjectCount))
        );
    }


    @Nested
    class GetAllFindingsGroupedByVulnerabilityCountTests {

        @Test
        void testCountWithHideSuppressionsHideInactive() {
            Long count = qm.getAllFindingsGroupedByVulnerabilityCount(Collections.emptyMap(), false, false);
            assertNotNull(count, "Count should not be null");
            assertEquals(4, count, "Count incorrect");
        }


        @Test
        void testCountWithShowSuppressionsHideInactive() {
            Long count = qm.getAllFindingsGroupedByVulnerabilityCount(Collections.emptyMap(), true, false);
            assertNotNull(count, "Count should not be null");
            assertEquals(4, count, "Count incorrect");
        }


        @Test
        void testCountWithHideSuppressionsShowInactive() {
            Long count = qm.getAllFindingsGroupedByVulnerabilityCount(Collections.emptyMap(), false, true);
            assertNotNull(count, "Count should not be null");
            assertEquals(4, count, "Count incorrect");
        }


        @Test
        void testCountWithShowSuppressionsShowInactive() {
            Long count = qm.getAllFindingsGroupedByVulnerabilityCount(Collections.emptyMap(), true, true);
            assertNotNull(count, "Count should not be null");
            assertEquals(4, count, "Count incorrect");
        }

    }


    @Nested
    class SortingTests {

        @Test
        void testSortingByVulnIdDesc() {

            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.vulnId");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.DESCENDING);
            qm = new QueryManager(alpineRequest);

            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), true, true);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(4, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, contains(
                    hasVulnerabilityWith("INT-2025-00004", 10L),
                    hasVulnerabilityWith("INT-2025-00003", 10L),
                    hasVulnerabilityWith("INT-2025-00002", 10L),
                    hasVulnerabilityWith("INT-2025-00001", 10L)
            ));
        }


        @Test
        void testSortingByVulnIdAsc() {

            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.vulnId");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.ASCENDING);
            qm = new QueryManager(alpineRequest);

            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), true, true);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(4, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, contains(
                    hasVulnerabilityWith("INT-2025-00001", 10L),
                    hasVulnerabilityWith("INT-2025-00002", 10L),
                    hasVulnerabilityWith("INT-2025-00003", 10L),
                    hasVulnerabilityWith("INT-2025-00004", 10L)
            ));
        }


        @Test
        void testSortingBySeverityDescWithSecondaryVulnIdDesc() {

            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.severity");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.DESCENDING);
            qm = new QueryManager(alpineRequest);

            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), true, true);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(4, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, contains(
                    hasVulnerabilityWith("INT-2025-00002", 10L), // Crit
                    hasVulnerabilityWith("INT-2025-00003", 10L), // Med
                    hasVulnerabilityWith("INT-2025-00004", 10L), // Med
                    hasVulnerabilityWith("INT-2025-00001", 10L)  // Unassigned
            ));
        }


        @Test
        void testSortingBySeverityDescWithSecondaryVulnIdAsc() {

            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.severity");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.ASCENDING);
            qm = new QueryManager(alpineRequest);

            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), true, true);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(4, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, contains(
                    hasVulnerabilityWith("INT-2025-00001", 10L), // Unassigned
                    hasVulnerabilityWith("INT-2025-00003", 10L), // Med
                    hasVulnerabilityWith("INT-2025-00004", 10L), // Med
                    hasVulnerabilityWith("INT-2025-00002", 10L)  // Crit
            ));
        }
    }


    @Nested
    class PaginationTests {

        @Test
        void testPaginationWithLargePageSizeReturnsSinglePage() {

            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getPagination()).thenReturn(new Pagination(Pagination.Strategy.OFFSET, 0, 100));
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.vulnId");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.DESCENDING);
            qm = new QueryManager(alpineRequest);

            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), false, false);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(4, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, contains(
                    hasVulnerabilityWith("INT-2025-00004", 8L),
                    hasVulnerabilityWith("INT-2025-00003", 8L),
                    hasVulnerabilityWith("INT-2025-00002", 8L),
                    hasVulnerabilityWith("INT-2025-00001", 1L)
            ));
        }


        @Test
        void testPaginationWithPageSizeOfTwoCheckFirstPage() {

            // Set up pagination behaviour - max of 2 results per page
            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getPagination()).thenReturn(new Pagination(Pagination.Strategy.PAGES, 1, 2));
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.vulnId");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.DESCENDING);
            qm = new QueryManager(alpineRequest);

            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), false, false);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(2, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, contains(
                    hasVulnerabilityWith("INT-2025-00004", 8L),
                    hasVulnerabilityWith("INT-2025-00003", 8L)
            ));
        }


        @Test
        void testPaginationWithPageSizeOfTwoCheckSecondPage() {

            // Set up pagination behaviour - max of 2 results per page
            AlpineRequest alpineRequest = Mockito.mock(AlpineRequest.class);
            Mockito.when(alpineRequest.getPagination()).thenReturn(new Pagination(Pagination.Strategy.PAGES, 2, 2));
            Mockito.when(alpineRequest.getOrderBy()).thenReturn("vulnerability.vulnId");
            Mockito.when(alpineRequest.getOrderDirection()).thenReturn(OrderDirection.DESCENDING);
            qm = new QueryManager(alpineRequest);

            // Page 2
            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), false, false);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Total item count incorrect");
            assertEquals(2, allFindingsGroupedByVulnerability.getList(GroupedFinding.class).size(), "Page item count incorrect");

            var findings2 = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings2, contains(
                    hasVulnerabilityWith("INT-2025-00002", 8L),
                    hasVulnerabilityWith("INT-2025-00001", 1L)
            ));
        }
    }


    @Nested
    class GetAllFindingsGroupedByVulnerabilityTests {

        @Test
        void getAllFindingsGroupedByVulnerabilityReturnsExpectedFindingsActiveProjectsExclSuppressed() {

            // Get findings - hide suppressed, hide inactive projects
            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), false, false);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Findings collection item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, containsInAnyOrder(
                    hasVulnerabilityWith("INT-2025-00001", 1L),
                    hasVulnerabilityWith("INT-2025-00002", 8L),
                    hasVulnerabilityWith("INT-2025-00003", 8L),
                    hasVulnerabilityWith("INT-2025-00004", 8L)
            ));

        }


        @Test
        void getAllFindingsGroupedByVulnerabilityReturnsExpectedFindingsActiveProjectsInclSuppressed() {

            // Get findings - show suppressed, hide inactive projects
            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), true, false);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Findings collection item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, containsInAnyOrder(
                    hasVulnerabilityWith("INT-2025-00001", 8L),
                    hasVulnerabilityWith("INT-2025-00002", 8L),
                    hasVulnerabilityWith("INT-2025-00003", 8L),
                    hasVulnerabilityWith("INT-2025-00004", 8L)
            ));

        }


        @Test
        void getAllFindingsGroupedByVulnerabilityReturnsExpectedFindingsActiveAndInactiveProjectsExclSuppressed() {

            // Get findings - hide suppressed, show inactive projects
            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), false, true);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Findings collection item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, containsInAnyOrder(
                    hasVulnerabilityWith("INT-2025-00001", 2L),
                    hasVulnerabilityWith("INT-2025-00002", 10L),
                    hasVulnerabilityWith("INT-2025-00003", 10L),
                    hasVulnerabilityWith("INT-2025-00004", 10L)
            ));

        }


        @Test
        void getAllFindingsGroupedByVulnerabilityReturnsExpectedFindingsActiveAndInactiveProjectsInclSuppressed() {

            // Get findings - show suppressed, show inactive projects
            PaginatedResult allFindingsGroupedByVulnerability = qm.getAllFindingsGroupedByVulnerability(Collections.emptyMap(), true, true);
            assertNotNull(allFindingsGroupedByVulnerability, "Findings should not be null");
            assertEquals(4, allFindingsGroupedByVulnerability.getTotal(), "Findings collection item count incorrect");

            var findings = allFindingsGroupedByVulnerability.getList(GroupedFinding.class);

            assertThat(findings, containsInAnyOrder(
                    hasVulnerabilityWith("INT-2025-00001", 10L),
                    hasVulnerabilityWith("INT-2025-00002", 10L),
                    hasVulnerabilityWith("INT-2025-00003", 10L),
                    hasVulnerabilityWith("INT-2025-00004", 10L)
            ));
        }

    }


}