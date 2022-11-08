package org.dependencytrack.tasks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_RETENTION_POLICY;

import alpine.model.IConfigProperty.PropertyType;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;
import javax.jdo.Query;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.ApplyRetentionPolicyEvent;
import org.dependencytrack.model.Bom.Format;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ApplyRetentionPolicyTaskTest extends PersistenceCapableTest {

    private final static String PROJECT_A = "PROJECT_A";
    private final static String PROJECT_B = "PROJECT_B";
    private final static String PROJECT_C = "PROJECT_C";
    private final String keepNRecent;
    private final int initialProjectACount;
    private final int expectedProjectACount;
    private final int initialProjectBCount;
    private final int expectedProjectBCount;
    private final int initialProjectCCount;
    private final int expectedProjectCCount;

    public ApplyRetentionPolicyTaskTest(String keepNRecent, int initialProjectACount, int expectedProjectACount,
            int initialProjectBCount, int expectedProjectBCount, int initialProjectCCount, int expectedProjectCCount) {
        this.keepNRecent = keepNRecent;
        this.initialProjectACount = initialProjectACount;
        this.expectedProjectACount = expectedProjectACount;
        this.initialProjectBCount = initialProjectBCount;
        this.expectedProjectBCount = expectedProjectBCount;
        this.initialProjectCCount = initialProjectCCount;
        this.expectedProjectCCount = expectedProjectCCount;
    }

    @Parameterized.Parameters(name = "[{index}] "
            + "keepNRecent={0} "
            + "initialProjectACount={1} expectedProjectACount={2}"
            + "initialProjectBCount={3} expectedProjectBCount={4}"
            + "initialProjectCCount={5} expectedProjectCCount={6}"
    )
    public static Collection testParameters() {
        return Arrays.asList(new Object[][]{
                // 1 project
                {null, 0, 0, 0, 0, 0, 0},
                {"-42", 0, 0, 0, 0, 0, 0},
                {"two", 0, 0, 0, 0, 0, 0},
                {"5", 0, 0, 0, 0, 0, 0},
                {null, 3, 3, 0, 0, 0, 0},
                {"-42", 3, 3, 0, 0, 0, 0},
                {"two", 3, 3, 0, 0, 0, 0},
                {"5", 3, 3, 0, 0, 0, 0},
                {null, 45, 45, 0, 0, 0, 0},
                {"-42", 45, 45, 0, 0, 0, 0},
                {"two", 45, 45, 0, 0, 0, 0},
                {"45", 45, 45, 0, 0, 0, 0},
                {"5", 45, 5, 0, 0, 0, 0},
                {"33", 100, 33, 0, 0, 0, 0},
                // 2 projects
                {null, 3, 3, 9, 9, 0, 0},
                {"-42", 3, 3, 7, 7, 0, 0},
                {"two", 3, 3, 4, 4, 0, 0},
                {"5", 3, 3, 2, 2, 0, 0},
                {null, 45, 45, 22, 22, 0, 0},
                {"-42", 45, 45, 1, 1, 0, 0},
                {"two", 45, 45, 3, 3, 0, 0},
                {"45", 45, 45, 7, 7, 0, 0},
                {"5", 46, 5, 3, 3, 0, 0},
                {"5", 46, 5, 5, 5, 0, 0},
                {"5", 46, 5, 8, 5, 0, 0},
                {"11", 44, 11, 10, 10, 0, 0},
                {"11", 44, 11, 11, 11, 0, 0},
                {"11", 44, 11, 12, 11, 0, 0},
                // 3 projects
                {null, 3, 3, 9, 9, 4, 4},
                {"-42", 3, 3, 7, 7, 5, 5},
                {"two", 3, 3, 4, 4, 4, 4},
                {"5", 3, 3, 2, 2, 8, 5},
                {null, 45, 45, 22, 22, 11, 11},
                {"-42", 45, 45, 1, 1, 3, 3},
                {"two", 45, 45, 3, 3, 5, 5},
                {"10", 9, 9, 10, 10, 11, 10},
                {"4", 9, 4, 10, 4, 11, 4},
        });
    }

    @Test
    public void parameterizedTest() throws Exception {
        // Arrange
        initializeProject(PROJECT_A, initialProjectACount);
        initializeProject(PROJECT_B, initialProjectBCount);
        initializeProject(PROJECT_C, initialProjectCCount);
        initializeConfigProperty(keepNRecent);
        // Act
        new ApplyRetentionPolicyTask().inform(new ApplyRetentionPolicyEvent());
        // Assert
        assertProject(PROJECT_A, initialProjectACount, expectedProjectACount);
        assertProject(PROJECT_B, initialProjectBCount, expectedProjectBCount);
        assertProject(PROJECT_C, initialProjectCCount, expectedProjectCCount);
    }

    private void assertProject(final String projectName, final int initialProjectCount, final int expectedProjectCount)
            throws Exception {
        assertThat(getProjectCount(projectName)).isEqualTo(expectedProjectCount);
        if (initialProjectCount > 0) {
            assertThat(getVersions(projectName)).contains(String.valueOf(initialProjectCount));
        }
    }

    private void initializeProject(final String projectName, final int initialProjectCount) {
        for (int i = 1; i <= initialProjectCount; i++) {
            final var project = qm.createProject(projectName, null, "" + i, null, null, null, true, false);
            project.setLastBomImport(new Date());
            project.setLastBomImportFormat(Format.CYCLONEDX.getFormatShortName());
            qm.persist(project);
        }
    }

    private void initializeConfigProperty(final String keepLastN) {
        qm.createConfigProperty(
                GENERAL_RETENTION_POLICY.getGroupName(),
                GENERAL_RETENTION_POLICY.getPropertyName(),
                keepLastN,
                PropertyType.INTEGER,
                null
        );
    }

    private long getProjectCount(final String projectName) throws Exception {
        try (final Query<Project> query = qm.getPersistenceManager()
                .newQuery(Project.class, "name == '" + projectName + "'")) {
            query.setResult("count(this)");
            return query.executeResultUnique(Long.class);
        }
    }

    private Set<String> getVersions(final String projectName) {
        try (final QueryManager qm = new QueryManager()) {
            return qm.getProjects().getList(Project.class)
                    .stream()
                    .filter(project -> projectName.equals(projectName))
                    .map(Project::getVersion)
                    .collect(Collectors.toSet());
        }
    }
}