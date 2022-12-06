package org.dependencytrack.tasks.scanners;

import alpine.model.IConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.SnykAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_API_VERSION;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ORG_ID;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class SnykMockServerTest extends PersistenceCapableTest {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(SCANNER_SNYK_ENABLED.getGroupName(),
                SCANNER_SNYK_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "snyk");
        qm.createConfigProperty(SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                "86400",
                IConfigProperty.PropertyType.STRING,
                "cache");
        qm.createConfigProperty(SCANNER_SNYK_API_TOKEN.getGroupName(),
                SCANNER_SNYK_API_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("token"),
                IConfigProperty.PropertyType.STRING,
                "token");
        qm.createConfigProperty(SCANNER_SNYK_ORG_ID.getGroupName(),
                SCANNER_SNYK_ORG_ID.getPropertyName(),
                "orgid",
                IConfigProperty.PropertyType.STRING,
                "orgid");
        qm.createConfigProperty(SCANNER_SNYK_API_VERSION.getGroupName(),
                SCANNER_SNYK_API_VERSION.getPropertyName(),
                "version",
                IConfigProperty.PropertyType.STRING,
                "version");
        qm.createConfigProperty(SCANNER_SNYK_BASE_URL.getGroupName(),
                SCANNER_SNYK_BASE_URL.getPropertyName(),
                "http://localhost:1080",
                IConfigProperty.PropertyType.STRING,
                "url");
    }

    @After
    public void tearDown() {
        mockServer.reset();
    }

    @AfterClass
    public static void afterClass() {
        mockServer.stop();
    }

    @Test
    public void testAnalyzer() throws Exception {
        String mockIndexResponse = readResourceFileToString("/unit/snyk.jsons/https---localhost-1080-api-v1-vulnerability-source-SNYK-vuln-snyk_vuln.json");
        mockServer
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
                                .withQueryStringParameter("version", "version")
                )
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                                .withBody(mockIndexResponse)
                );

        Project project = new Project();
        project.setId(123);
        project.setName("xyz");
        Component component = new Component();
        component.setName("test");
        component.setProject(project);
        component.setId(0);
        component.setPurl(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0"));
        component.setPurlCoordinates("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0");
        component = qm.createComponent(component, false);
        SnykAnalysisTask task = new SnykAnalysisTask();
        SnykAnalysisEvent event = new SnykAnalysisEvent(component);
        task.inform(event);

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("SNYK", "SNYK-JAVA-COMFASTERXMLWOODSTOX-2928754", true);
        Assert.assertNotNull(vulnerability);
        Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
        Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
        Assert.assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", vulnerability.getCvssV3Vector());
        Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
        Assert.assertNotNull(vulnerability.getCreated());
        Assert.assertNotNull(vulnerability.getAliases());
        Assert.assertEquals(1, vulnerability.getAliases().size());
        Assert.assertEquals("A", vulnerability.getAliases().get(0).getCveId());
        Assert.assertTrue(qm.contains(vulnerability, component));
    }

    @Test
    public void testAnalyzeWithError() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
                        .withQueryStringParameter("version", "version"))
                .respond(response()
                        .withStatusCode(400)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withBody("""
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
                                """));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0");
        component.setPurlCoordinates("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(List.of(component)));
    }

    private String readResourceFileToString(String fileName) throws Exception {
        return Files.readString(Paths.get(getClass().getResource(fileName).toURI()));
    }

}