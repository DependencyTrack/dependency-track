package org.dependencytrack.tasks;

import alpine.event.framework.EventService;
import com.github.packageurl.PackageURL;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.http.Body;
import com.github.tomakehurst.wiremock.http.ContentTypeHeader;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.tasks.repositories.RepositoryMetaAnalyzerTask;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import jakarta.ws.rs.core.MediaType;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

public class RepoMetaAnalysisTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options().port(2345));

    @Before
    public void setUp() {
        qm.createConfigProperty(ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(), "43200000",
                ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyType(),
                ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getDescription());
        wireMockRule.start();
    }

    @After
    public void tearDown() {
        EventService.getInstance().unsubscribe(RepositoryMetaAnalyzerTask.class);
        wireMockRule.stop();
    }

    @Test
    public void informTestNullPassword() throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.anyUrl()).withHeader("Authorization", containing("Basic"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withResponseBody(Body.ofBinaryOrText("""
                                                               <metadata>
                                                               <groupId>junit</groupId>
                                                               <artifactId>junit</artifactId>
                                                               <versioning>
                                                               <latest>4.13.2</latest>
                                                               <release>4.13.2</release>
                                                               <versions>
                                                               <version>4.13-beta-1</version>
                                                               <version>4.13-beta-2</version>
                                                               <version>4.13-beta-3</version>
                                                               <version>4.13-rc-1</version>
                                                               <version>4.13-rc-2</version>
                                                               <version>4.13</version>
                                                               <version>4.13.1</version>
                                                               <version>4.13.2</version>
                                                               </versions>
                                                               <lastUpdated>20210213164433</lastUpdated>
                                                               </versioning>
                                                               </metadata>
                                """.getBytes(), new ContentTypeHeader(MediaType.APPLICATION_JSON))
                        )
                        .withHeader("X-CheckSum-MD5", "md5hash")
                        .withHeader("X-Checksum-SHA1", "sha1hash")
                        .withHeader("X-Checksum-SHA512", "sha512hash")
                        .withHeader("X-Checksum-SHA256", "sha256hash")
                        .withHeader("Last-Modified", "Thu, 07 Jul 2022 14:00:00 GMT")));
        EventService.getInstance().subscribe(RepositoryMetaEvent.class, RepositoryMetaAnalyzerTask.class);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("junit");
        component.setPurl(new PackageURL("pkg:maven/junit/junit@4.12"));
        qm.createComponent(component, false);
        qm.createRepository(RepositoryType.MAVEN, "test", wireMockRule.baseUrl(), true, false, true, "testuser", null, null);
        new RepositoryMetaAnalyzerTask().inform(new RepositoryMetaEvent(List.of(component)));
        RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "junit", "junit");
        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent.getLatestVersion()).isEqualTo("4.13.2");
    }

    @Test
    public void informTestNullUserName() throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.anyUrl()).withHeader("Authorization", containing("Basic"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withResponseBody(Body.ofBinaryOrText("""
                                                               <metadata>
                                                               <groupId>test1</groupId>
                                                               <artifactId>test1</artifactId>
                                                               <versioning>
                                                               <latest>1.7.0</latest>
                                                               <release>1.7.0</release>
                                                               <versions>
                                                               <version>1.2.0</version>
                                                               <version>1.3.0</version>
                                                               <version>1.4.0</version>
                                                               <version>1.5.0</version>
                                                               <version>1.5-rc-1</version>
                                                               <version>1.6.0</version>
                                                               <version>1.6.3</version>
                                                               <version>1.7.0</version>
                                                               </versions>
                                                               <lastUpdated>20210213164433</lastUpdated>
                                                               </versioning>
                                                               </metadata>
                                """.getBytes(), new ContentTypeHeader(MediaType.APPLICATION_JSON))
                        )
                        .withHeader("X-CheckSum-MD5", "md5hash")
                        .withHeader("X-Checksum-SHA1", "sha1hash")
                        .withHeader("X-Checksum-SHA512", "sha512hash")
                        .withHeader("X-Checksum-SHA256", "sha256hash")
                        .withHeader("Last-Modified", "Thu, 07 Jul 2022 14:00:00 GMT")));
        EventService.getInstance().subscribe(RepositoryMetaEvent.class, RepositoryMetaAnalyzerTask.class);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("test1");
        component.setPurl(new PackageURL("pkg:maven/test1/test1@1.2.0"));
        qm.createComponent(component, false);
        qm.createRepository(RepositoryType.MAVEN, "test", wireMockRule.baseUrl(), true, false, true, null, "testPassword", null);
        new RepositoryMetaAnalyzerTask().inform(new RepositoryMetaEvent(List.of(component)));
        RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "test1", "test1");
        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.7.0");
    }

    @Test
    public void informTestNullUserNameAndPassword() throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.anyUrl())
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withResponseBody(Body.ofBinaryOrText("""
                                                               <metadata>
                                                               <groupId>test2</groupId>
                                                               <artifactId>test2</artifactId>
                                                               <versioning>
                                                               <latest>4.13.2</latest>
                                                               <release>4.13.2</release>
                                                               <versions>
                                                               <version>4.13-beta-1</version>
                                                               <version>4.13-beta-2</version>
                                                               <version>4.13-beta-3</version>
                                                               <version>4.13-rc-1</version>
                                                               <version>4.13-rc-2</version>
                                                               <version>4.13</version>
                                                               <version>4.13.1</version>
                                                               <version>4.13.2</version>
                                                               </versions>
                                                               <lastUpdated>20210213164433</lastUpdated>
                                                               </versioning>
                                                               </metadata>
                                """.getBytes(), new ContentTypeHeader(MediaType.APPLICATION_JSON))
                        )
                        .withHeader("X-CheckSum-MD5", "md5hash")
                        .withHeader("X-Checksum-SHA1", "sha1hash")
                        .withHeader("X-Checksum-SHA512", "sha512hash")
                        .withHeader("X-Checksum-SHA256", "sha256hash")
                        .withHeader("Last-Modified", "Thu, 07 Jul 2022 14:00:00 GMT")));
        EventService.getInstance().subscribe(RepositoryMetaEvent.class, RepositoryMetaAnalyzerTask.class);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("junit");
        component.setPurl(new PackageURL("pkg:maven/test2/test2@4.12"));
        qm.createComponent(component, false);
        qm.createRepository(RepositoryType.MAVEN, "test", wireMockRule.baseUrl(), true, false, false, null, null, null);
        new RepositoryMetaAnalyzerTask().inform(new RepositoryMetaEvent(List.of(component)));
        RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "test2", "test2");
        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent.getLatestVersion()).isEqualTo("4.13.2");
    }

    @Test
    public void informTestUserNameAndPassword() throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.anyUrl()).withHeader("Authorization", containing("Basic"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withResponseBody(Body.ofBinaryOrText("""
                                                               <metadata>
                                                               <groupId>test3</groupId>
                                                               <artifactId>test3</artifactId>
                                                               <versioning>
                                                               <latest>4.13.2</latest>
                                                               <release>4.13.2</release>
                                                               <versions>
                                                               <version>4.13-beta-1</version>
                                                               <version>4.13-beta-2</version>
                                                               <version>4.13-beta-3</version>
                                                               <version>4.13-rc-1</version>
                                                               <version>4.13-rc-2</version>
                                                               <version>4.13</version>
                                                               <version>4.13.1</version>
                                                               <version>4.13.2</version>
                                                               </versions>
                                                               <lastUpdated>20210213164433</lastUpdated>
                                                               </versioning>
                                                               </metadata>
                                """.getBytes(), new ContentTypeHeader(MediaType.APPLICATION_JSON))
                        )
                        .withHeader("X-CheckSum-MD5", "md5hash")
                        .withHeader("X-Checksum-SHA1", "sha1hash")
                        .withHeader("X-Checksum-SHA512", "sha512hash")
                        .withHeader("X-Checksum-SHA256", "sha256hash")
                        .withHeader("Last-Modified", "Thu, 07 Jul 2022 14:00:00 GMT")));
        EventService.getInstance().subscribe(RepositoryMetaEvent.class, RepositoryMetaAnalyzerTask.class);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("test3");
        component.setPurl(new PackageURL("pkg:maven/test3/test3@4.12"));
        qm.createComponent(component, false);
        qm.createRepository(RepositoryType.MAVEN, "test", wireMockRule.baseUrl(), true, false, true, "testUser", "testPassword", null);
        new RepositoryMetaAnalyzerTask().inform(new RepositoryMetaEvent(List.of(component)));
        RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "test3", "test3");
        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent.getLatestVersion()).isEqualTo("4.13.2");
    }

    @Test
    public void informTestBearerToken() throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.anyUrl()).withHeader("Authorization", containing("Bearer"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withResponseBody(Body.ofBinaryOrText("""
                                                               <metadata>
                                                               <groupId>test4</groupId>
                                                               <artifactId>test4</artifactId>
                                                               <versioning>
                                                               <latest>4.13.2</latest>
                                                               <release>4.13.2</release>
                                                               <versions>
                                                               <version>4.13-beta-1</version>
                                                               <version>4.13-beta-2</version>
                                                               <version>4.13-beta-3</version>
                                                               <version>4.13-rc-1</version>
                                                               <version>4.13-rc-2</version>
                                                               <version>4.13</version>
                                                               <version>4.13.1</version>
                                                               <version>4.13.2</version>
                                                               </versions>
                                                               <lastUpdated>20210213164433</lastUpdated>
                                                               </versioning>
                                                               </metadata>
                                """.getBytes(), new ContentTypeHeader(MediaType.APPLICATION_JSON))
                        )
                        .withHeader("X-CheckSum-MD5", "md5hash")
                        .withHeader("X-Checksum-SHA1", "sha1hash")
                        .withHeader("X-Checksum-SHA512", "sha512hash")
                        .withHeader("X-Checksum-SHA256", "sha256hash")
                        .withHeader("Last-Modified", "Thu, 07 Jul 2022 14:00:00 GMT")));
        EventService.getInstance().subscribe(RepositoryMetaEvent.class, RepositoryMetaAnalyzerTask.class);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("test4");
        component.setPurl(new PackageURL("pkg:maven/test4/test4@4.12"));
        qm.createComponent(component, false);
        qm.createRepository(RepositoryType.MAVEN, "test", wireMockRule.baseUrl(), true, false, true, null, null, "bearer_token");
        new RepositoryMetaAnalyzerTask().inform(new RepositoryMetaEvent(List.of(component)));
        RepositoryMetaComponent metaComponent = qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "test4", "test4");
        qm.getPersistenceManager().refresh(metaComponent);
        assertThat(metaComponent.getLatestVersion()).isEqualTo("4.13.2");
    }

}
