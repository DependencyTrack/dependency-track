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
    public void testParseOSVJsonToAdvisoryAndSave() {

        try {
            // parse OSV json file to Advisory object
            GoogleOSVAdvisoryParser parser = new GoogleOSVAdvisoryParser();
            String file = "src/test/resources/unit/tasks/repositories/https---osv-GHSA-77rv-6vfw-x4gc.json";
            String jsonString = readFileAsString(file);
            JSONObject jsonObject = new JSONObject(jsonString);
            OSVAdvisory advisory = parser.parse(jsonObject);
            LOGGER.info("Advisory parsed is "+advisory);
            Assert.assertNotNull(advisory);
            Assert.assertEquals(advisory.getId(), "GHSA-77rv-6vfw-x4gc");
            Assert.assertEquals(advisory.getSeverity(), "CRITICAL");
            Assert.assertTrue(advisory.getCweIds().contains("CWE-601"));
            Assert.assertEquals(advisory.getVulnerabilities().size(), 8);
            Assert.assertEquals(advisory.getVulnerabilities().get(0).getUpperVersionRange(), "2.0.17");
            Assert.assertEquals(advisory.getVulnerabilities().get(0).getPurl(), "pkg:maven/org.springframework.security.oauth/spring-security-oauth");

            // pass the mapped advisory to OSV task to update the database
            final var task = new OSVDownloadTask();
            task.updateDatasource(advisory);
            var qm = new QueryManager();
            final var vulnerableSoftware = qm.getVulnerableSoftwareByPurl("pkg:maven/org.springframework.security.oauth/spring-security-oauth", "2.0.17", "0");
            Assert.assertNotNull(vulnerableSoftware);
            Assert.assertEquals(vulnerableSoftware.getPurlNamespace(), "MAVEN");

        } catch (Exception ex) {
            LOGGER.error("Exception reading JSON file");
        }
    }

    public static String readFileAsString(String file) throws Exception
    {
        return new String(Files.readAllBytes(Paths.get(file)));
    }
}