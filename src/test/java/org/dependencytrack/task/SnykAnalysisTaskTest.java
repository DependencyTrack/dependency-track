package org.dependencytrack.task;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.tasks.scanners.SnykAnalysisTask;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class SnykAnalysisTaskTest extends PersistenceCapableTest {

    private JSONObject jsonObject;

    private SnykAnalysisTask task = new SnykAnalysisTask();

    @Test
    public void testParseVersionRanges() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("ranges");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = task.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(3, vulnerableSoftwares.size());

        VulnerableSoftware vs = vulnerableSoftwares.get(0);
        Assert.assertEquals("npm", vs.getPurlType());
        Assert.assertEquals("bootstrap-table", vs.getPurlName());
        Assert.assertEquals("", vs.getVersionStartIncluding());
        Assert.assertEquals("2.12.6.1", vs.getVersionEndExcluding());

        vs = vulnerableSoftwares.get(1);
        Assert.assertEquals("2.13.0", vs.getVersionStartIncluding());
        Assert.assertEquals("2.13.2.1", vs.getVersionEndExcluding());

        vs = vulnerableSoftwares.get(2);
        Assert.assertEquals(null, vs.getVersionStartIncluding());
        Assert.assertEquals("1.20.2", vs.getVersionEndExcluding());
    }
}
