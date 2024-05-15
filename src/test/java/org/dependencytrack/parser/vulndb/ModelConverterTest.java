package org.dependencytrack.parser.vulndb;

import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.vulndb.model.CvssV3Metric;
import org.dependencytrack.parser.vulndb.model.Results;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;

public class ModelConverterTest {
    private List<?> resultList;

    @Before
    public void setUp() throws Exception {
        String filePath = "src/test/resources/unit/vulndb.jsons/vulnerabilities_0.json";
        File file = new File(filePath);
        final VulnDbParser parser = new VulnDbParser();
        try {
        final Results<Vulnerability> results = parser.parse(file, org.dependencytrack.parser.vulndb.model.Vulnerability.class);
        resultList = results.getResults();
        } catch (IOException ex) {
            fail("Failed to parse file: " + ex.getMessage());
        }
    }
    @Test
    public void testConvert() {
        final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln = (org.dependencytrack.parser.vulndb.model.Vulnerability) resultList.get(0);
        Vulnerability vulnerability = ModelConverter.convert(mock(QueryManager.class), vulnDbVuln);
        assertNotNull(vulnerability);
        assertEquals("1", vulnerability.getVulnId());
        assertEquals("test title", vulnerability.getTitle());
        assertEquals("(AV:N/AC:M/Au:N/C:P/I:N/A:N)", vulnerability.getCvssV2Vector());
        assertEquals("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", vulnerability.getCvssV3Vector());
        assertEquals(BigDecimal.valueOf(4.3), vulnerability.getCvssV2BaseScore());
        assertEquals(BigDecimal.valueOf(4.3), vulnerability.getCvssV3BaseScore());
        assertEquals("* [http://example.com](http://example.com)\n", vulnerability.getReferences());
        VulnerabilityAlias alias = vulnerability.getAliases().get(0);
        assertEquals("CVE-1234-0000", alias.getCveId());
    }
    @Test
    public void testConvertWithoutNvdAdditionalInfo() {
        final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln = (org.dependencytrack.parser.vulndb.model.Vulnerability) resultList.get(1);
        Vulnerability vulnerability = ModelConverter.convert(mock(QueryManager.class), vulnDbVuln);
        assertNotNull(vulnerability);
        for (final CvssV3Metric metric : vulnDbVuln.cvssV3Metrics()) {
            assertEquals("1234-0000" ,metric.cveId());
        }
        VulnerabilityAlias alias = vulnerability.getAliases().get(0);
        assertEquals("CVE-1234-0000", alias.getCveId());
    }
    @Test
    public void testConvertWithoutAnyCve() {
            final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln = (org.dependencytrack.parser.vulndb.model.Vulnerability) resultList.get(2);
            Vulnerability vulnerability = ModelConverter.convert(mock(QueryManager.class), vulnDbVuln);
            assertNotNull(vulnerability);
            for (final CvssV3Metric metric : vulnDbVuln.cvssV3Metrics()) {
                assertNull(metric.cveId());
            }
            assertNull(vulnerability.getAliases());

    }
}