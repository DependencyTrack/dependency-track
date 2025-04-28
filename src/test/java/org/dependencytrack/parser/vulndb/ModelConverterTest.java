package org.dependencytrack.parser.vulndb;

import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.vulndb.model.CvssV3Metric;
import org.dependencytrack.parser.vulndb.model.Results;
import org.dependencytrack.persistence.QueryManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;

class ModelConverterTest {
    private List<?> resultList;

    @BeforeEach
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
    void testConvert() {
        final OffsetDateTime odt = OffsetDateTime.parse("2021-12-20T21:34:04Z");
        final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln = (org.dependencytrack.parser.vulndb.model.Vulnerability) resultList.get(0);
        Vulnerability vulnerability = ModelConverter.convert(mock(QueryManager.class), vulnDbVuln);
        Assertions.assertNotNull(vulnerability);
        Assertions.assertEquals("1", vulnerability.getVulnId());
        Assertions.assertEquals("test title", vulnerability.getTitle());
        Assertions.assertEquals(Date.from(odt.toInstant()), vulnerability.getUpdated());
        Assertions.assertEquals("AV:N/AC:M/Au:N/C:P/I:N/A:N", vulnerability.getCvssV2Vector());
        Assertions.assertEquals("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", vulnerability.getCvssV3Vector());
        Assertions.assertEquals(BigDecimal.valueOf(4.3), vulnerability.getCvssV2BaseScore());
        Assertions.assertEquals(BigDecimal.valueOf(4.3), vulnerability.getCvssV3BaseScore());
        Assertions.assertEquals("* [http://example.com](http://example.com)\n", vulnerability.getReferences());
        VulnerabilityAlias alias = vulnerability.getAliases().get(0);
        Assertions.assertEquals("CVE-1234-0000", alias.getCveId());
    }
    @Test
    void testConvertWithoutNvdAdditionalInfo() {
        final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln = (org.dependencytrack.parser.vulndb.model.Vulnerability) resultList.get(1);
        Vulnerability vulnerability = ModelConverter.convert(mock(QueryManager.class), vulnDbVuln);
        Assertions.assertNotNull(vulnerability);
        for (final CvssV3Metric metric : vulnDbVuln.cvssV3Metrics()) {
            Assertions.assertEquals("1234-0000", metric.cveId());
        }
        VulnerabilityAlias alias = vulnerability.getAliases().get(0);
        Assertions.assertEquals("CVE-1234-0000", alias.getCveId());
    }
    @Test
    void testConvertWithoutAnyCve() {
            final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln = (org.dependencytrack.parser.vulndb.model.Vulnerability) resultList.get(2);
            Vulnerability vulnerability = ModelConverter.convert(mock(QueryManager.class), vulnDbVuln);
            Assertions.assertNotNull(vulnerability);
            for (final CvssV3Metric metric : vulnDbVuln.cvssV3Metrics()) {
                Assertions.assertNull(metric.cveId());
            }
            Assertions.assertNull(vulnerability.getAliases());

    }
}