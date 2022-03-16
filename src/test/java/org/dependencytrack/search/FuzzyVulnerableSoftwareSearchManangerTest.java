package org.dependencytrack.search;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.util.List;

import static org.mockito.Mockito.*;

import static org.junit.Assert.*;

public class FuzzyVulnerableSoftwareSearchManangerTest {

    private FuzzyVulnerableSoftwareSearchMananger toTest = new FuzzyVulnerableSoftwareSearchMananger(true);
    private QueryManager qm;

    @Before
    public void setUp() throws Exception {
        qm = mock(QueryManager.class);
        when(qm.getObjectByUuid(any(), anyString())).thenReturn(new VulnerableSoftware());
    }

    @Test
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
    }

    @Test
    public void getCpeRegexp() {
        assertEquals("cpe23:/cpe\\:2\\.3\\:a\\:.*/", FuzzyVulnerableSoftwareSearchMananger.getCpeRegexp("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"));
    }

    @Test
    public void testSearch() throws Exception {
        //String luceneQueryString = "product:libexpat1~0.8"; //product:libexpat1~0.8 AND
        SearchManager sm = new SearchManager();
        //The tilde makes it fuzzy. e.g. Will match libexpat1 to libexpat and product exact matches with vendor mismatch
        String nextTerm = FuzzyVulnerableSoftwareSearchMananger.getCpeRegexp("cpe:2.3:a:*:time:*:*:*:*:*:*:*:*");
        // grab first wildcarded component
        String fuzzyNextTerm = nextTerm.substring(0, nextTerm.indexOf(".*") + 2) + "/";
        SearchResult sr = toTest.searchIndex("product:\\\"time\\\"");
        assertFalse(sr.getResults().isEmpty());
    }

    @Test
    public void parse() throws CpeParsingException {
        Cpe cpe = CpeParser.parse("cpe:2.3:a:*:libglib-2.0-0:1:2.70.0:*:*:*:*:*:*:*");
                //new Cpe(Part.APPLICATION, "*", "*", "2:23", "*", "*", "*", "*", "*", "*", "*");
    }
}