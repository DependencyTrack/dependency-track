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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.snyk;

import alpine.model.IConfigProperty;
import org.json.JSONArray;
import org.json.JSONObject;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.snyk.model.SnykError;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_API_USERNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_CVSS_SOURCE;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ENABLED;

public class SnykParserTest extends PersistenceCapableTest {

    private SnykParser parser;

    @Before
    public void setUp() {
        parser = new SnykParser();
    }

    @Test
    public void testParseVersionRanges() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("range0");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = parser.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(1, vulnerableSoftwares.size());

        VulnerableSoftware vs = vulnerableSoftwares.get(0);
        Assert.assertEquals("2.13.0", vs.getVersionStartIncluding());
        Assert.assertEquals("2.13.2.1", vs.getVersionEndExcluding());
    }

    @Test
    public void testParseVersionRangesStar() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("range2");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = parser.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(0, vulnerableSoftwares.size());
    }

    @Test
    public void testParseVersionIndefiniteRanges() throws IOException {

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/ranges.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        JSONArray ranges = jsonObject.optJSONArray("range1");
        String purl = "pkg:npm/bootstrap-table@1.20.0";
        List<VulnerableSoftware> vulnerableSoftwares = parser.parseVersionRanges(qm, purl, ranges);
        Assert.assertNotNull(vulnerableSoftwares);
        Assert.assertEquals(0, vulnerableSoftwares.size());
    }

    @Test
    public void testParseSeveritiesNvd() throws IOException {

        // By default NVD is first priority for CVSS, no need to set config property.
        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/severities.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        JSONArray severities = jsonObject.optJSONArray("severities1");
        JSONObject cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities2");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("SNYK", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities5");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("RHEL", cvss.optString("source"));
    }

    @Test
    public void testParseSeveritiesSnyk() throws IOException {

        qm.createConfigProperty(SCANNER_SNYK_CVSS_SOURCE.getGroupName(),
                SCANNER_SNYK_CVSS_SOURCE.getPropertyName(),
                "SNYK",
                IConfigProperty.PropertyType.STRING,
                "First priority source for cvss calculation");

        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/severities.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        JSONArray severities = jsonObject.optJSONArray("severities1");
        JSONObject cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("SNYK", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities3");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));

        severities = jsonObject.optJSONArray("severities4");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("RHEL", cvss.optString("source"));
    }

    @Test
    public void testGetSnykCvssConfig() {
        qm.createConfigProperty(SCANNER_SNYK_API_TOKEN.getGroupName(),
                SCANNER_SNYK_API_TOKEN.getPropertyName(),
                "token",
                IConfigProperty.PropertyType.STRING,
                "token");
        qm.createConfigProperty(SCANNER_OSSINDEX_API_USERNAME.getGroupName(),
                SCANNER_OSSINDEX_API_USERNAME.getPropertyName(),
                "username",
                IConfigProperty.PropertyType.STRING,
                "username");

        String config = parser.getSnykCvssConfig(SCANNER_SNYK_CVSS_SOURCE);
        Assert.assertNotNull(config);
        Assert.assertEquals("NVD", config);
        config = parser.getSnykCvssConfig(SCANNER_SNYK_ENABLED);
        Assert.assertNotNull(config);
        Assert.assertEquals("false", config);
        config = parser.getSnykCvssConfig(SCANNER_SNYK_API_TOKEN);
        Assert.assertNotNull(config);
        Assert.assertEquals("token", config);
        config = parser.getSnykCvssConfig(SCANNER_OSSINDEX_API_USERNAME);
        Assert.assertNotNull(config);
        Assert.assertEquals("username", config);
    }

    @Test
    public void testSelectCvssObjectBasedOnSource() throws IOException {
        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/snyk.jsons/severities.json")));
        final JSONObject jsonObject = new JSONObject(jsonString);
        JSONArray severities = jsonObject.optJSONArray("severities1");
        JSONObject cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss.optString("vector"));

        severities = jsonObject.optJSONArray("severities4");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("RHEL", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss.optString("vector"));

        severities = jsonObject.optJSONArray("severities2");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("SNYK", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P", cvss.optString("vector"));
        severities = jsonObject.optJSONArray("severities3");
        cvss = parser.selectCvssObjectBasedOnSource(severities);
        Assert.assertNotNull(cvss);
        Assert.assertEquals("NVD", cvss.optString("source"));
        Assert.assertEquals("high", cvss.optString("level"));
        Assert.assertEquals("7.5", cvss.optString("score"));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss.optString("vector"));
    }

    @Test
    public void testParseErrors() {
        final JSONObject jsonObject = new JSONObject("""
                {
                   "jsonapi": {
                     "version": "1.0"
                   },
                   "errors": [
                     {
                       "id": "0f12fd75-c80a-4c15-929b-f7794eb3dd4f",
                       "links": {
                         "about": "https://docs.snyk.io/more-info/error-catalog#snyk-ossi-2010-invalid-purl-has-been-provided"
                       },
                       "status": "400",
                       "code": "SNYK-OSSI-2010",
                       "title": "Invalid PURL has been provided",
                       "detail": "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0%",
                       "source": {
                         "pointer": "/orgs/0d581750-c5d7-4acf-9ff9-4a5bae31cbf1/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0%25/issues"
                       },
                       "meta": {
                         "links": [
                           "https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst"
                         ]
                       }
                     }
                   ]
                 }
                """);
        final List<SnykError> errors = parser.parseErrors(jsonObject);
        assertThat(errors).hasSize(1);

        final SnykError error = errors.get(0);
        assertThat(error.code()).isEqualTo("SNYK-OSSI-2010");
        assertThat(error.title()).isEqualTo("Invalid PURL has been provided");
        assertThat(error.detail()).isEqualTo("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0%");
    }

    @Test
    public void testParseErrorsWhenInputIsNull() {
        assertThat(parser.parseErrors(null)).isEmpty();
    }

    @Test
    public void testParseErrorsWhenInputHasNoErrorsField() {
        assertThat(parser.parseErrors(new JSONObject("{}"))).isEmpty();
    }

}