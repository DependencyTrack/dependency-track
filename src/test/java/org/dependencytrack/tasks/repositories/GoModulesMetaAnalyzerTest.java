package org.dependencytrack.tasks.repositories;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.Assert;
import org.junit.Test;

public class GoModulesMetaAnalyzerTest {

    @Test
    public void testAnalyzer() throws Exception {
        final var component = new Component();
        component.setVersion("v0.1.0");
        component.setPurl(new PackageURL("pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0"));

        final var analyzer = new GoModulesMetaAnalyzer();
        Assert.assertTrue(analyzer.isApplicable(component));
        Assert.assertEquals(RepositoryType.GO_MODULES, analyzer.supportedRepositoryType());

        MetaModel metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertTrue(metaModel.getLatestVersion().startsWith("v"));
        Assert.assertNotNull(metaModel.getPublishedTimestamp());

        component.setVersion("0.1.0");
        metaModel = analyzer.analyze(component);
        Assert.assertNotNull(metaModel.getLatestVersion());
        Assert.assertFalse(metaModel.getLatestVersion().startsWith("v"));
    }

    @Test
    public void testCaseEncode() {
        final var analyzer = new GoModulesMetaAnalyzer();

        Assert.assertEquals("!cyclone!d!x", analyzer.caseEncode("CycloneDX"));
        Assert.assertEquals("cyclonedx", analyzer.caseEncode("cyclonedx"));
    }

}
