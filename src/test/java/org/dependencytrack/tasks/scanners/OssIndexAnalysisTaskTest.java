package org.dependencytrack.tasks.scanners;

import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import com.github.tomakehurst.wiremock.client.BasicCredentials;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.OssIndexAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import jakarta.json.Json;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_API_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_API_USERNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED;

public class OssIndexAnalysisTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    private OssIndexAnalysisTask analysisTask;

    @Before
    public void setUp() {
        qm.createConfigProperty(
                SCANNER_OSSINDEX_ENABLED.getGroupName(),
                SCANNER_OSSINDEX_ENABLED.getPropertyName(),
                "true",
                SCANNER_OSSINDEX_ENABLED.getPropertyType(),
                SCANNER_OSSINDEX_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getDefaultPropertyValue(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyType(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getDescription()
        );

        analysisTask = new OssIndexAnalysisTask(wireMock.baseUrl());
    }

    @Test
    public void testIsCapable() {
        final var asserts = new SoftAssertions();

        for (final Map.Entry<String, Boolean> test : Map.of(
                "pkg:maven/com.fasterxml.woodstox/woodstox-core", false, // Missing version
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", true,
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz", true
        ).entrySet()) {
            final var component = new Component();
            component.setPurl(test.getKey());
            asserts.assertThat(analysisTask.isCapable(component)).isEqualTo(test.getValue());
        }

        asserts.assertAll();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsCurrent() throws Exception {
        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, wireMock.baseUrl(),
                Vulnerability.Source.OSSINDEX.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz", new Date(),
                Json.createObjectBuilder()
                        .add("vulnIds", Json.createArrayBuilder().add(123))
                        .build());

        assertThat(analysisTask.shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0"))).isTrue();
        assertThat(analysisTask.shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.0"))).isTrue();
        assertThat(analysisTask.shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isFalse();
    }

    @Test
    public void testAnalyzeWithRateLimiting() {
        wireMock.stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .inScenario("rateLimit")
                .willReturn(aResponse()
                        .withStatus(429))
                .willSetStateTo("secondAttempt"));

        wireMock.stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .inScenario("rateLimit")
                .whenScenarioStateIs("secondAttempt")
                .willReturn(aResponse()
                        .withStatus(429))
                .willSetStateTo("thirdAttempt"));

        wireMock.stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .inScenario("rateLimit")
                .whenScenarioStateIs("thirdAttempt")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.ossindex.component-report.v1+json")
                        .withBody("""
                                [
                                  {
                                    "coordinates": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
                                    "description": "General data-binding functionality for Jackson: works on core streaming API",
                                    "reference": "https://ossindex.sonatype.org/component/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                                    "vulnerabilities": [
                                      {
                                        "id": "CVE-2020-36518",
                                        "displayName": "CVE-2020-36518",
                                        "title": "[CVE-2020-36518] CWE-787: Out-of-bounds Write",
                                        "description": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.\\n\\nSonatype's research suggests that this CVE's details differ from those defined at NVD. See https://ossindex.sonatype.org/vulnerability/CVE-2020-36518 for details",
                                        "cvssScore": 7.5,
                                        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                        "cwe": "CWE-787",
                                        "cve": "CVE-2020-36518",
                                        "reference": "https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                                        "externalReferences": [
                                          "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518",
                                          "https://github.com/FasterXML/jackson-databind/issues/2816"
                                        ]
                                      }
                                    ]
                                  }
                                ]
                                """)));

        var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.13.1");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> analysisTask.inform(new OssIndexAnalysisEvent(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).satisfiesExactly(
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("CVE-2020-36518");
                    assertThat(vuln.getSource()).isEqualTo("NVD");
                    assertThat(vuln.getTitle()).isNull();
                    assertThat(vuln.getDescription()).isEqualTo("""
                            jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.
                                                    
                            Sonatype's research suggests that this CVE's details differ from those defined at NVD. See https://ossindex.sonatype.org/vulnerability/CVE-2020-36518 for details""");
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
                    assertThat(vuln.getCvssV3BaseScore()).isEqualByComparingTo("7.5");
                    assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNotNull();
                    assertThat(vuln.getCvssV3ImpactSubScore()).isNotNull();
                    assertThat(vuln.getCwes()).containsOnly(787);
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0](https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0)
                            * [http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518](http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518)
                            * [https://github.com/FasterXML/jackson-databind/issues/2816](https://github.com/FasterXML/jackson-databind/issues/2816)""");
                }
        );

        wireMock.verify(exactly(3), postRequestedFor(urlPathEqualTo("/api/v3/component-report"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent()))
                .withRequestBody(equalToJson("""
                        {
                          "coordinates": [
                            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
                          ]
                        }
                        """)));
    }

    @Test
    public void testAnalyzeWithAuthentication() throws Exception {
        qm.createConfigProperty(
                SCANNER_OSSINDEX_API_USERNAME.getGroupName(),
                SCANNER_OSSINDEX_API_USERNAME.getPropertyName(),
                "foo",
                SCANNER_OSSINDEX_API_USERNAME.getPropertyType(),
                SCANNER_OSSINDEX_API_USERNAME.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_OSSINDEX_API_TOKEN.getGroupName(),
                SCANNER_OSSINDEX_API_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("apiToken"),
                SCANNER_OSSINDEX_API_TOKEN.getPropertyType(),
                SCANNER_OSSINDEX_API_TOKEN.getDescription()
        );

        wireMock.stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.ossindex.component-report.v1+json")
                        .withBody("[]")));

        var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.13.1");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> analysisTask.inform(new OssIndexAnalysisEvent(component)));

        wireMock.verify(postRequestedFor(urlPathEqualTo("/api/v3/component-report"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent()))
                .withBasicAuth(new BasicCredentials("foo", "apiToken"))
                .withRequestBody(equalToJson("""
                        {
                          "coordinates": [
                            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
                          ]
                        }
                        """)));
    }

    @Test
    public void testAnalyzeWithApiTokenDecryptionError() {
        qm.createConfigProperty(
                SCANNER_OSSINDEX_API_USERNAME.getGroupName(),
                SCANNER_OSSINDEX_API_USERNAME.getPropertyName(),
                "foo",
                SCANNER_OSSINDEX_API_USERNAME.getPropertyType(),
                SCANNER_OSSINDEX_API_USERNAME.getDescription()
        );
        qm.createConfigProperty(
                SCANNER_OSSINDEX_API_TOKEN.getGroupName(),
                SCANNER_OSSINDEX_API_TOKEN.getPropertyName(),
                "notAnEncryptedValue",
                SCANNER_OSSINDEX_API_TOKEN.getPropertyType(),
                SCANNER_OSSINDEX_API_TOKEN.getDescription()
        );

        wireMock.stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.ossindex.component-report.v1+json")
                        .withBody("[]")));

        var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.13.1");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> analysisTask.inform(new OssIndexAnalysisEvent(component)));

        wireMock.verify(postRequestedFor(urlPathEqualTo("/api/v3/component-report"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("User-Agent", equalTo(ManagedHttpClientFactory.getUserAgent()))
                .withoutHeader("Authorization")
                .withRequestBody(equalToJson("""
                        {
                          "coordinates": [
                            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
                          ]
                        }
                        """)));
    }

}