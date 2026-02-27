package org.dependencytrack.search;

import alpine.Config;
import alpine.persistence.PaginatedResult;
import org.apache.commons.io.FileUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.document.VulnerableSoftwareDocument;
import org.dependencytrack.tasks.scanners.InternalAnalysisTask;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.search.IndexConstants.VULNERABLESOFTWARE_UUID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class FuzzyVulnerableSoftwareSearchManagerTest extends PersistenceCapableTest {
    private static final File INDEX_DIRECTORY;
    private static final File INDEX_TEMP_DIRECTORY;
    private FuzzyVulnerableSoftwareSearchManager toTest = new FuzzyVulnerableSoftwareSearchManager(true);
    private QueryManager mockQm;
    private final VulnerableSoftware VALUE_TO_MATCH = new VulnerableSoftware();
    static {
        INDEX_DIRECTORY = new File(
                Config.getInstance().getDataDirectorty(),
                "index" + File.separator + IndexManager.IndexType.VULNERABLESOFTWARE.name().toLowerCase());
        INDEX_TEMP_DIRECTORY = new File(INDEX_DIRECTORY.getAbsolutePath() + "_tmp");
    }

    @BeforeAll
    public static void saveVsIndex() throws IOException {
        VulnerableSoftwareIndexer.getInstance().close();
        if (INDEX_TEMP_DIRECTORY.exists()) {
            FileUtils.deleteDirectory(INDEX_TEMP_DIRECTORY);
        }
        if (INDEX_DIRECTORY.exists()) {
            INDEX_DIRECTORY.renameTo(INDEX_TEMP_DIRECTORY);
        }
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setUuid(UUID.randomUUID());
        vs.setCpe23("cpe:2.3:a:libexpat_project:libexpat:2.2.2:*:*:*:*:*:*:*");
        vs.setProduct("libexpat");
        VulnerableSoftwareIndexer.getInstance().add(new VulnerableSoftwareDocument(vs));
        commitIndex();
    }
    @AfterAll
    public static void restoreVsIndex() throws IOException {
        VulnerableSoftwareIndexer.getInstance().close();
        if (INDEX_DIRECTORY.exists()) {
            FileUtils.deleteDirectory(INDEX_DIRECTORY);
        }
        if (INDEX_TEMP_DIRECTORY.exists()) {
            Assertions.assertTrue(INDEX_TEMP_DIRECTORY.renameTo(INDEX_DIRECTORY));
        }
    }

    @BeforeEach
    public void setUp() throws Exception {
        mockQm = mock(QueryManager.class);
        when(mockQm.getObjectByUuid(any(), anyString())).thenReturn(VALUE_TO_MATCH);
    }

    @Test
    void fuzzyAnalysis() throws CpeParsingException, CpeValidationException {
        us.springett.parsers.cpe.Cpe justThePart = new us.springett.parsers.cpe.Cpe(Part.APPLICATION, "*", "*", "*", "*", "*", "*", "*", "*", "*", "*");
        // wildcard all components after part to constrain fuzzing to components of same type e.g. application, operating-system
        String fuzzyTerm = FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp(justThePart.toCpe23FS());
        SearchResult searchResult = FuzzyVulnerableSoftwareSearchManager.searchIndex("product:libexpat1~0.88 AND " + fuzzyTerm);
        // Oddly validating lucene first cuz can't decouple from that.
        assertEquals(1, searchResult.getResults().size());
        assertEquals(1, searchResult.getResults().values().iterator().next().size());

        Component component = new Component();
        component.setName("libexpat1");
        component.setCpe("cpe:2.3:a:libexpat_project:libexpat1:2.0.0:*:*:*:*:*:*:*");
        Cpe cpe = CpeParser.parse(component.getCpe());
        List<VulnerableSoftware> vs = toTest.fuzzyAnalysis(mockQm, component, cpe);
        Assertions.assertFalse(vs.isEmpty());
        assertSame(VALUE_TO_MATCH, vs.get(0));

    }

    @Test
    void getLuceneCpeRegexp() throws CpeValidationException, CpeEncodingException {
        us.springett.parsers.cpe.Cpe os = new us.springett.parsers.cpe.Cpe( Part.OPERATING_SYSTEM, "vendor", "product", "1\\.0", "2", "33","en", "inside", "Vista", "x86", "other");

        assertEquals("cpe23:/cpe\\:2\\.3\\:a\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*\\:.*/", FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"));
        assertEquals("cpe23:/cpe\\:2\\.3\\:o\\:vendor\\:product\\:1.0\\:2\\:33\\:en\\:inside\\:vista\\:x86\\:other/", FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp(os.toCpe23FS()));
        assertEquals("cpe22:/cpe\\:\\/o\\:vendor\\:product\\:1.0\\:2\\:33\\:en/", FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp(os.toCpe22Uri()));
    }

    @Test
    @Disabled("This demonstrates assumptions about CPE matching but does not exercise code")
    void cpeMatching() {
        String lucene = FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp("cpe:2.3:a:*:file:*:*:*:*:*:*:*:*");
        String regex = lucene.substring(7, lucene.length()-1);
        Pattern pattern = Pattern.compile(regex);
        Assertions.assertFalse(pattern.matcher(
        "cpe:2.3:a:dell:emc_vnx2_operating_environment:*:*:*:*:*:file:*:*").matches());
        Assertions.assertTrue(pattern.matcher(
                "cpe:2.3:a:*:file:*:*:*:*:*:file:*:*").matches());
    }

    @Test
    void fuzzySearchDropsMissingEntities() {
        var qm = mock(QueryManager.class);

        var id1 = UUID.randomUUID();
        var id2 = UUID.randomUUID();
        var results = List.of(
                Map.of(VULNERABLESOFTWARE_UUID, id1.toString()),
                Map.of(VULNERABLESOFTWARE_UUID, id2.toString())
        );

        var vs = mock(VulnerableSoftware.class);
        when(qm.getObjectByUuid(VulnerableSoftware.class, id1.toString())).thenReturn(null);
        when(qm.getObjectByUuid(VulnerableSoftware.class, id2.toString())).thenReturn(vs);

        var searchResult = mock(SearchResult.class);
        when(searchResult.getResults()).thenReturn(Map.of("vulnerablesoftware", results));

        List<VulnerableSoftware> fuzzyResult;
        try (var fvssm = mockStatic(FuzzyVulnerableSoftwareSearchManager.class)) {
            fvssm.when(() -> FuzzyVulnerableSoftwareSearchManager.searchIndex("query")).thenReturn(searchResult);
            fvssm.when(() -> FuzzyVulnerableSoftwareSearchManager.fuzzySearch(qm, "query")).thenCallRealMethod();

            fuzzyResult = FuzzyVulnerableSoftwareSearchManager.fuzzySearch(qm, "query");

            fvssm.verify(() -> FuzzyVulnerableSoftwareSearchManager.searchIndex("query"));
        }

        verify(qm).getObjectByUuid(VulnerableSoftware.class, id1.toString());
        verify(qm).getObjectByUuid(VulnerableSoftware.class, id2.toString());

        assertEquals(1, fuzzyResult.size());
        assertSame(vs, fuzzyResult.getFirst());
    }

    @Test
    void fuzzySearchReturnsEmptyListIfNoResults() {
        var qm = mock(QueryManager.class);

        var searchResult = mock(SearchResult.class);
        when(searchResult.getResults()).thenReturn(Map.of());

        List<VulnerableSoftware> fuzzyResult;
        try (var fvssm = mockStatic(FuzzyVulnerableSoftwareSearchManager.class)) {
            fvssm.when(() -> FuzzyVulnerableSoftwareSearchManager.searchIndex("query")).thenReturn(searchResult);
            fvssm.when(() -> FuzzyVulnerableSoftwareSearchManager.fuzzySearch(qm, "query")).thenCallRealMethod();

            fuzzyResult = FuzzyVulnerableSoftwareSearchManager.fuzzySearch(qm, "query");

            fvssm.verify(() -> FuzzyVulnerableSoftwareSearchManager.searchIndex("query"));
        }

        verify(qm, never()).getObjectByUuid(any(), anyString());

        assertEquals(0, fuzzyResult.size());
    }

    @Test
    void testFoundByFuzzingFlagInTwoProjects() throws CpeParsingException, CpeEncodingException, CpeValidationException {

        qm.createConfigProperty(
                ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED.getGroupName(),
                ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED.getPropertyType(),
                null
        );

        String cpeUri = "cpe:2.3:a:*:libexpat:*:*:*:*:*:*:*:*";
        VulnerableSoftware vulnerableSoftware = ModelConverter.convertCpe23UriToVulnerableSoftware(cpeUri);
        vulnerableSoftware.setVersionEndExcluding("2.3.0");
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        // Add to Lucene index so fuzzy matching can find it
        VulnerableSoftwareIndexer.getInstance().add(new VulnerableSoftwareDocument(vulnerableSoftware));
        commitIndex();

        // Create vulnerability linked to the vulnerable software
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2024-TEST-001");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        // Create first project with exact CPE match (foundByFuzzing should be false)
        Project projectExact = new Project();
        projectExact.setName("project-exact-match");
        projectExact = qm.createProject(projectExact, Collections.emptyList(), false);

        Component cpeComponentExact = new Component();
        cpeComponentExact.setProject(projectExact);
        cpeComponentExact.setGroup("libexpat_project");
        cpeComponentExact.setName("libexpat");
        cpeComponentExact.setVersion("2.2.2");
        cpeComponentExact.setCpe("cpe:2.3:a:libexpat_project:libexpat:2.2.2:*:*:*:*:*:*:*");
        cpeComponentExact = qm.createComponent(cpeComponentExact, false);

        // Analyze exact match component
        new InternalAnalysisTask().analyze(List.of(cpeComponentExact));

        // Verify exact match has the vulnerability with foundByFuzzing = false
        final PaginatedResult vulnerabilitiesExact = qm.getVulnerabilities(cpeComponentExact);
        assertThat(vulnerabilitiesExact.getTotal()).isEqualTo(1);
        assertThat(vulnerabilitiesExact.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2024-TEST-001");

        final FindingAttribution attributionExact = qm.getFindingAttribution(vulnerability, cpeComponentExact);
        assertThat(attributionExact).isNotNull();
        assertThat(attributionExact.getFoundByFuzzing()).isFalse(); // Exact match, not found by fuzzing

        // Create second project with component that requires fuzzy matching
        Project projectFuzzy = new Project();
        projectFuzzy.setName("project-fuzzy-match");
        projectFuzzy = qm.createProject(projectFuzzy, Collections.emptyList(), false);

        Component purlComponentFuzzy = new Component();
        purlComponentFuzzy.setProject(projectFuzzy);
        purlComponentFuzzy.setGroup("libexpat_project");
        purlComponentFuzzy.setName("libexpat1");
        purlComponentFuzzy.setVersion("2.2.2");
        purlComponentFuzzy.setPurl("pkg:generic/libexpat_project/libexpat1@2.2.2");
        purlComponentFuzzy = qm.createComponent(purlComponentFuzzy, false);

        // Analyze fuzzy match component
        new InternalAnalysisTask().analyze(List.of(purlComponentFuzzy));

        final FindingAttribution attributionFuzzy = qm.getFindingAttribution(vulnerability, purlComponentFuzzy);
        assertThat(attributionFuzzy).isNotNull();
        assertThat(attributionFuzzy.getFoundByFuzzing()).isTrue(); // Fuzzy match, found by fuzzing

    }

    private static void commitIndex() {
        IndexManagerTestUtil.commitIndex(VulnerableSoftwareIndexer.getInstance());
    }
}