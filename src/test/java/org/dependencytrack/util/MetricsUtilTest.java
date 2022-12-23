package org.dependencytrack.util;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.tasks.metrics.Counters;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Date;

public class MetricsUtilTest {
    
    private static ProjectMetrics getProjectMetrics(long id, Date firstOccurrence, Date lastOccurrence) {
        var project = new Project();
        project.setId(id);

        var pm = new Counters(lastOccurrence).createProjectMetrics(project);
        pm.setFirstOccurrence(firstOccurrence);
        
        return pm;
    }

    @Test
    public void testSortedSum() throws Exception {
        final var d1 = DateUtil.parseShortDate("20221220");
        final var d2 = DateUtil.parseShortDate("20221222");
        final var d3 = DateUtil.parseShortDate("20230101");
        var list = new ArrayList<ProjectMetrics>();
        list.add(getProjectMetrics(2, d1, d2));
        list.add(getProjectMetrics(1, d2, d2));
        list.add(getProjectMetrics(2, d3, d3));

        final var results = MetricsUtils.sum(list, true);
        Assert.assertEquals(3, results.size());
        Assert.assertEquals(d1, results.get(0).getFirstOccurrence());

        Assert.assertEquals(1, results.get(0).getProjects());
        Assert.assertEquals(d2, results.get(1).getFirstOccurrence());
        Assert.assertEquals(2, results.get(1).getProjects());
        Assert.assertEquals(d3, results.get(2).getFirstOccurrence());
        Assert.assertEquals(2, results.get(2).getProjects());
    }

    @Test
    public void testUnsortedSum() throws Exception {
        final var d1 = DateUtil.parseShortDate("20221220");
        final var d2 = DateUtil.parseShortDate("20221222");
        final var d3 = DateUtil.parseShortDate("20230101");
        var list = new ArrayList<ProjectMetrics>();
        list.add(getProjectMetrics(1, d2, d2));
        list.add(getProjectMetrics(2, d3, d3));
        list.add(getProjectMetrics(2, d1, d2));

        final var results = MetricsUtils.sum(list, false);
        Assert.assertEquals(3, results.size());
        Assert.assertEquals(d1, results.get(0).getFirstOccurrence());

        Assert.assertEquals(1, results.get(0).getProjects());
        Assert.assertEquals(d2, results.get(1).getFirstOccurrence());
        Assert.assertEquals(2, results.get(1).getProjects());
        Assert.assertEquals(d3, results.get(2).getFirstOccurrence());
        Assert.assertEquals(2, results.get(2).getProjects());
    }
}
