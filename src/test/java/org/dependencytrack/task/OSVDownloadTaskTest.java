/*
 * Copyright 2022 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dependencytrack.task;

import alpine.common.logging.Logger;
import kong.unirest.json.JSONObject;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.parser.osv.GoogleOSVAdvisoryParser;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.OSVDownloadTask;
import org.junit.Assert;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

public class OSVDownloadTaskTest extends PersistenceCapableTest {

    private static final Logger LOGGER = Logger.getLogger(OSVDownloadTaskTest.class);

    @Test
    public void testParseOSVJsonToAdvisoryAndSave() throws Exception {

        // parse OSV json file to Advisory object
        GoogleOSVAdvisoryParser parser = new GoogleOSVAdvisoryParser();
        String file = "src/test/resources/unit/osv.jsons/osv-GHSA-77rv-6vfw-x4gc.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(file)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OSVAdvisory advisory = parser.parse(jsonObject);
        LOGGER.info("Advisory parsed is "+advisory);
        Assert.assertNotNull(advisory);
        Assert.assertEquals(advisory.getVulnerabilities().size(), 8);

        // pass the mapped advisory to OSV task to update the database
        final var task = new OSVDownloadTask();
        task.updateDatasource(advisory);
        var qm = new QueryManager();
        var vulnerableSoftware = qm.getVulnerableSoftwareByPurl("pkg:maven/org.springframework.security.oauth/spring-security-oauth", "2.0.17", "0");
        Assert.assertNotNull(vulnerableSoftware);
        Assert.assertEquals(vulnerableSoftware.getPurlType(), "Maven");
        Assert.assertEquals(vulnerableSoftware.getVersionStartIncluding(), "0");
        Assert.assertEquals(vulnerableSoftware.getVersionEndExcluding(), "2.0.17");

        vulnerableSoftware = qm.getVulnerableSoftwareByPurl("pkg:maven/org.springframework.security.oauth/spring-security-oauth", "2.1.4", "2.1.0");
        Assert.assertNotNull(vulnerableSoftware);
        Assert.assertEquals(vulnerableSoftware.getPurlType(), "Maven");
        Assert.assertEquals(vulnerableSoftware.getVersionStartIncluding(), "2.1.0");
        Assert.assertEquals(vulnerableSoftware.getVersionEndExcluding(), "2.1.4");
    }

    @Test
    public void testWithdrawnAdvisory() throws Exception {

        GoogleOSVAdvisoryParser parser = new GoogleOSVAdvisoryParser();
        String file = "src/test/resources/unit/osv.jsons/osv-withdrawn.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(file)));
        JSONObject jsonObject = new JSONObject(jsonString);
        OSVAdvisory advisory = parser.parse(jsonObject);
        LOGGER.info("Advisory parsed is "+advisory);
        Assert.assertNull(advisory);
    }
}