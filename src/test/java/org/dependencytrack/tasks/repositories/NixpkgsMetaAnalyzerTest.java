package org.dependencytrack.tasks.repositories;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class NixpkgsMetaAnalyzerTest {
    @Test
    void testAnalyzer() throws Exception {
        final var component1 = new Component();
        final var component2 = new Component();
        component1.setPurl(new PackageURL("pkg:nixpkgs/SDL_sound@1.0.3"));
        component2.setPurl(new PackageURL("pkg:nixpkgs/amarok@2.9.71"));
        final var analyzer = new NixpkgsMetaAnalyzer();
        Assertions.assertTrue(analyzer.isApplicable(component1));
        Assertions.assertTrue(analyzer.isApplicable(component2));
        Assertions.assertEquals(RepositoryType.NIXPKGS, analyzer.supportedRepositoryType());
        Assertions.assertNotNull(analyzer.analyze(component1).getLatestVersion());
        Assertions.assertNotNull(analyzer.analyze(component2).getLatestVersion());
    }
}
