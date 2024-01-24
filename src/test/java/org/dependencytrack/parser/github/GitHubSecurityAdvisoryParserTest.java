package org.dependencytrack.parser.github;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.dependencytrack.parser.github.graphql.GitHubSecurityAdvisoryParser;
import org.dependencytrack.parser.github.graphql.model.GitHubSecurityAdvisory;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

public class GitHubSecurityAdvisoryParserTest {

    GitHubSecurityAdvisoryParser parser = new GitHubSecurityAdvisoryParser();

    @Test
    public void testWithdrawnAdvisory() throws IOException {

        String jsonFile = "src/test/resources/unit/github.jsons/GHSA-8v27-2fg9-7h62.json";
        String jsonString = new String(Files.readAllBytes(Paths.get(jsonFile)));
        JSONObject jsonObject = new JSONObject(jsonString);
        List<GitHubSecurityAdvisory> advisories = parser.parse(jsonObject).getAdvisories();
        Assert.assertEquals(0, advisories.size());
    }

}
