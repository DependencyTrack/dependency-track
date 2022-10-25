package org.dependencytrack.tasks.scanners;

import com.github.packageurl.PackageURL;
import kong.unirest.json.JSONObject;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.persistence.CweImporter;
import org.dependencytrack.tasks.OsvDownloadTask;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class VulnerableSoftwareVersionTest extends PersistenceCapableTest {

    private JSONObject jsonObject;
    private SnykAnalysisTask taskSnyk = new SnykAnalysisTask();
    private final OsvAdvisoryParser parserOsv = new OsvAdvisoryParser();
    private OsvDownloadTask taskOsv = new OsvDownloadTask();

    @Test
    public void testReportedByAndLastUpdateForVulnerableSoftwareVersion() throws Exception {

        // Snyk analysis of purl npm/moment
        new CweImporter().processCweDefinitions(); // Necessary for resolving CWEs

        prepareJsonObject("src/test/resources/unit/snyk.jsons/snyk-purl-moment.json");
        Component component = new Component();
        component.setPurl("pkg:npm/moment@2.24.0");
        component.setUuid(UUID.randomUUID());
        component.setName("test-snyk");

        taskSnyk.handle(component, jsonObject, 200);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:npm/moment"));
        Assert.assertEquals(1, vulnerableSoftware.size());
        Assert.assertEquals("2", vulnerableSoftware.get(0).getVersionStartIncluding());
        Assert.assertEquals("5", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assert.assertEquals("SNYK", vulnerableSoftware.get(0).getReportedBy());
        Assert.assertEquals(Date.from(Instant.now()).toString(), vulnerableSoftware.get(0).getUpdated().toString());

        // OSV analysis of purl npm/moment
        prepareJsonObject("src/test/resources/unit/osv.jsons/osv-purl-moment.json");
        OsvAdvisory advisory = parserOsv.parse(jsonObject);
        taskOsv.updateDatasource(advisory);

        vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(new PackageURL("pkg:npm/moment"));
        Assert.assertEquals(2, vulnerableSoftware.size());
        Assert.assertEquals("SNYK", vulnerableSoftware.get(0).getReportedBy());
        Assert.assertEquals("OSV", vulnerableSoftware.get(1).getReportedBy());
        Assert.assertEquals("7", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("9", vulnerableSoftware.get(1).getVersionEndExcluding());
        Assert.assertEquals(Date.from(Instant.now()).toString(), vulnerableSoftware.get(1).getUpdated().toString());
    }

    private void prepareJsonObject(String filePath) throws IOException {
        // parse json file to Advisory object
        String jsonString = new String(Files.readAllBytes(Paths.get(filePath)));
        jsonObject = new JSONObject(jsonString);
    }
}
