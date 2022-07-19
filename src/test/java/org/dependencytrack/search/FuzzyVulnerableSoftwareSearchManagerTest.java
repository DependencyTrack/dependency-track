package org.dependencytrack.search;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.util.List;
import java.util.regex.Pattern;

import static org.mockito.Mockito.*;

import static org.junit.Assert.*;

public class FuzzyVulnerableSoftwareSearchManagerTest {

    private FuzzyVulnerableSoftwareSearchManager toTest = new FuzzyVulnerableSoftwareSearchManager(true);
    private QueryManager qm;

    @Before
    public void setUp() throws Exception {
        qm = mock(QueryManager.class);
        when(qm.getObjectByUuid(any(), anyString())).thenReturn(new VulnerableSoftware());
    }

    @Test
    @Ignore("This test exercises the code but relies on an existing lucene index")
    public void fuzzyAnalysis() throws CpeParsingException {
        Component component = new Component();
        component.setName("libexpat1");
        component.setCpe("cpe:2.3:a:libexpat_project:libexpat1:*:*:*:*:*:*:*:*");
        Cpe cpe = CpeParser.parse(component.getCpe());
        List<VulnerableSoftware> vs = toTest.fuzzyAnalysis(qm, component, cpe);
        assertFalse(vs.isEmpty());
        component.setName("an");
        component.setCpe("cpe:2.3:a:*:at:*:*:*:*:*:*:*:*");
        cpe = CpeParser.parse(component.getCpe());
        vs = toTest.fuzzyAnalysis(qm, component, cpe);
        assertFalse(vs.isEmpty());
        component.setName("mc");
        component.setCpe("cpe:2.3:a:*:mc:*:*:*:*:*:*:*:*");
        cpe = CpeParser.parse(component.getCpe());
        vs = toTest.fuzzyAnalysis(qm, component, cpe);
        assertTrue(vs.isEmpty());
    }

    @Test
    public void getLuceneCpeRegexp() throws CpeValidationException, CpeEncodingException {
        us.springett.parsers.cpe.Cpe os = new us.springett.parsers.cpe.Cpe( Part.OPERATING_SYSTEM, "vendor", "product", "1\\.0", "2", "33","en", "inside", "Vista", "x86", "other");

        assertEquals("cpe23:/cpe\\:2\\.3\\:a\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*/", FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"));
        assertEquals("cpe23:/cpe\\:2\\.3\\:o\\:vendor\\:product\\:1.0\\:2\\:33\\:en\\:inside\\:Vista\\:x86\\:other/", FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp(os.toCpe23FS()));
        assertEquals("cpe22:/cpe\\:\\/o\\:vendor\\:product\\:1.0\\:2\\:33\\:en/", FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp(os.toCpe22Uri()));
    }

    @Test
    @Ignore ("This demonstrates assumptions about CPE matching but does not exercise code")
    public void cpeMatching() {
        String lucene = FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp("cpe:2.3:a:*:file:*:*:*:*:*:*:*:*");
        String regex = lucene.substring(7, lucene.length()-1);
        Pattern pattern = Pattern.compile(regex);
        assertFalse(pattern.matcher(
        "cpe:2.3:a:dell:emc_vnx2_operating_environment:*:*:*:*:*:file:*:*").matches());
        assertTrue(pattern.matcher(
                "cpe:2.3:a:*:file:*:*:*:*:*:file:*:*").matches());
    }
}