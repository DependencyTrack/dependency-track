package org.dependencytrack.notification.publisher;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static com.icegreen.greenmail.configuration.GreenMailConfiguration.aConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_PREFIX;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_FROM_ADDR;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_PASSWORD;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SERVER_HOSTNAME;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SERVER_PORT;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_SSLTLS;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_TRUSTCERT;
import static org.dependencytrack.model.ConfigPropertyConstants.EMAIL_SMTP_USERNAME;

class SendMailPublisherTest extends AbstractPublisherTest<SendMailPublisher> {

    @RegisterExtension
    public static final GreenMailExtension greenMail = new GreenMailExtension(ServerSetup.SMTP.dynamicPort())
            .withConfiguration(aConfig().
                    withUser("username", "password"));

    public SendMailPublisherTest() {
        super(DefaultNotificationPublishers.EMAIL, new SendMailPublisher());
    }

    @BeforeEach
    public void setUp() throws Exception {
        qm.createConfigProperty(
                EMAIL_SMTP_ENABLED.getGroupName(),
                EMAIL_SMTP_ENABLED.getPropertyName(),
                "true",
                EMAIL_SMTP_ENABLED.getPropertyType(),
                EMAIL_SMTP_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_SERVER_HOSTNAME.getGroupName(),
                EMAIL_SMTP_SERVER_HOSTNAME.getPropertyName(),
                greenMail.getSmtp().getBindTo(),
                EMAIL_SMTP_SERVER_HOSTNAME.getPropertyType(),
                EMAIL_SMTP_SERVER_HOSTNAME.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_SERVER_PORT.getGroupName(),
                EMAIL_SMTP_SERVER_PORT.getPropertyName(),
                String.valueOf(greenMail.getSmtp().getPort()),
                EMAIL_SMTP_SERVER_PORT.getPropertyType(),
                EMAIL_SMTP_SERVER_PORT.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_USERNAME.getGroupName(),
                EMAIL_SMTP_USERNAME.getPropertyName(),
                "username",
                EMAIL_SMTP_USERNAME.getPropertyType(),
                EMAIL_SMTP_USERNAME.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_PASSWORD.getGroupName(),
                EMAIL_SMTP_PASSWORD.getPropertyName(),
                DataEncryption.encryptAsString("password"),
                EMAIL_SMTP_PASSWORD.getPropertyType(),
                EMAIL_SMTP_PASSWORD.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_FROM_ADDR.getGroupName(),
                EMAIL_SMTP_FROM_ADDR.getPropertyName(),
                "dtrack@example.com",
                EMAIL_SMTP_FROM_ADDR.getPropertyType(),
                EMAIL_SMTP_FROM_ADDR.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_PREFIX.getGroupName(),
                EMAIL_PREFIX.getPropertyName(),
                "[Dependency-Track]",
                EMAIL_PREFIX.getPropertyType(),
                EMAIL_PREFIX.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_SSLTLS.getGroupName(),
                EMAIL_SMTP_SSLTLS.getPropertyName(),
                "false",
                EMAIL_SMTP_SSLTLS.getPropertyType(),
                EMAIL_SMTP_SSLTLS.getDescription()
        );
        qm.createConfigProperty(
                EMAIL_SMTP_TRUSTCERT.getGroupName(),
                EMAIL_SMTP_TRUSTCERT.getPropertyName(),
                "false",
                EMAIL_SMTP_TRUSTCERT.getPropertyType(),
                EMAIL_SMTP_TRUSTCERT.getDescription()
        );
    }

    @Override
    public void testInformWithBomConsumedNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithBomConsumedNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Bill of Materials Consumed");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Bill of Materials Consumed
                                        
                    --------------------------------------------------------------------------------
                                        
                    Project:           projectName
                    Version:           projectVersion
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                                        
                    --------------------------------------------------------------------------------
                                        
                    A CycloneDX BOM was consumed and will be processed
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithBomProcessingFailedNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithBomProcessingFailedNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Bill of Materials Processing Failed");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Bill of Materials Processing Failed
                                        
                    --------------------------------------------------------------------------------
                                        
                    Project:           projectName
                    Version:           projectVersion
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                                        
                    --------------------------------------------------------------------------------
                                        
                    Cause:
                    cause
                                        
                    --------------------------------------------------------------------------------
                                        
                    An error occurred while processing a BOM
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithBomValidationFailedNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithBomValidationFailedNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Bill of Materials Validation Failed");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Bill of Materials Validation Failed
                                        
                    --------------------------------------------------------------------------------
                                        
                    Project:           projectName
                    Version:           projectVersion
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                    Errors:            [$.components[928].externalReferences[1].url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference]
                                        
                    --------------------------------------------------------------------------------
                                        
                    An error occurred during BOM Validation
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T00:20:34.000000888
                    """);
        });
    }

    @Override
    public void testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Bill of Materials Processing Failed");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Bill of Materials Processing Failed
                                        
                    --------------------------------------------------------------------------------
                                        
                    Project:           projectName
                    Version:           projectVersion
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                                        
                    --------------------------------------------------------------------------------
                                        
                    Cause:
                    cause
                                        
                    --------------------------------------------------------------------------------
                                        
                    An error occurred while processing a BOM
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithDataSourceMirroringNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithDataSourceMirroringNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] GitHub Advisory Mirroring");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    GitHub Advisory Mirroring
                                               
                    --------------------------------------------------------------------------------
                                        
                    Level:     ERROR
                    Scope:     SYSTEM
                    Group:     DATASOURCE_MIRRORING
                                        
                    --------------------------------------------------------------------------------
                                        
                    An error occurred mirroring the contents of GitHub Advisories. Check log for details.
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithNewVulnerabilityNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithNewVulnerabilityNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] New Vulnerability Identified");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    New Vulnerability Identified
                                        
                    --------------------------------------------------------------------------------
                                        
                    Vulnerability ID:  INT-001
                    Vulnerability URL: /vulnerability/?source=INTERNAL&vulnId=INT-001
                    Severity:          MEDIUM
                    Source:            INTERNAL
                    Component:         componentName : componentVersion
                    Component URL:     /component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                    Project:           projectName
                    Version:           projectVersion
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                                        
                    --------------------------------------------------------------------------------
                                        
                                        
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testPublishWithScheduledNewVulnerabilitiesNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testPublishWithScheduledNewVulnerabilitiesNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] New Vulnerabilities Summary");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringWhitespace("""
                    New Vulnerabilities Summary
                    
                    --------------------------------------------------------------------------------
                    
                    Overview:
                    - New Vulnerabilities: 1 (Suppressed: 1)
                    - Affected Projects:   1
                    - Affected Components: 1
                    - Since:               1970-01-01T00:01:06Z
                    
                    --------------------------------------------------------------------------------
                    
                    Project Summaries:
                    
                    - Project: [projectName : projectVersion]
                      Project URL: /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                    
                      + New Vulnerabilities Of Severity MEDIUM: 1 (Suppressed: 0)
                    
                    --------------------------------------------------------------------------------
                    
                    Vulnerability Details:
                    
                    - Project: [projectName : projectVersion]
                      Project URL: /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                    
                      + Vulnerability ID:       INT-001
                        Vulnerability Source:   INTERNAL
                        Vulnerability Severity: MEDIUM
                        Vulnerability URL:      /vulnerability/?source=INTERNAL&vulnId=INT-001
                        Component:              componentName : componentVersion
                        Component URL:          /component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                        Timestamp:              1970-01-01T18:31:06Z
                        Analysis State:         FALSE_POSITIVE
                        Suppressed:             true
                    
                    --------------------------------------------------------------------------------
                    
                    Identified 1 new vulnerabilities across 1 projects and 1 components since 1970-01-01T00:01:06Z, of which 1 are suppressed.
                    
                    --------------------------------------------------------------------------------
                    
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testPublishWithScheduledNewPolicyViolationsNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testPublishWithScheduledNewPolicyViolationsNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] New Policy Violations Summary");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);

            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringWhitespace("""
                    New Policy Violations Summary
                    
                    --------------------------------------------------------------------------------
                    
                    Overview:
                    - New Violations:      1 (Suppressed: 0)
                      - Of Type LICENSE: 1
                    - Affected Projects:   1
                    - Affected Components: 1
                    - Since:               1970-01-01T00:01:06Z
                    
                    --------------------------------------------------------------------------------
                    
                    Project Summaries:
                    
                    - Project: [projectName : projectVersion]
                      Project URL: /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                    
                      + New Violations Of Type LICENSE: 1 (Suppressed: 0)
                    
                    --------------------------------------------------------------------------------
                    
                    Violation Details:
                    
                    - Project: [projectName : projectVersion]
                      Project URL: /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                    
                      + Policy:                policyName
                        Policy Condition:      AGE NUMERIC_EQUAL P666D
                        Policy Violation Type: LICENSE
                        Component:             componentName : componentVersion
                        Component URL:         /component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                        Timestamp:             1970-01-01T18:31:06Z
                        Analysis State:        APPROVED
                        Suppressed:            false
                    
                    --------------------------------------------------------------------------------
                    
                    Identified 1 new policy violations across 1 project and 1 components since 1970-01-01T00:01:06Z, of which 0 are suppressed.
                    
                    --------------------------------------------------------------------------------
                    
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithNewVulnerableDependencyNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithNewVulnerableDependencyNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Vulnerable Dependency Introduced");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Vulnerable Dependency Introduced
                                        
                    --------------------------------------------------------------------------------
                                        
                    Project:           [projectName : projectVersion]
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                    Component:         componentName : componentVersion
                    Component URL:     /component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                                        
                    Vulnerabilities
                                        
                    Vulnerability ID:  INT-001
                    Vulnerability URL: /vulnerability/?source=INTERNAL&vulnId=INT-001
                    Severity:          MEDIUM
                    Source:            INTERNAL
                    Description:
                    vulnerabilityDescription
                                        
                                        
                                        
                    --------------------------------------------------------------------------------
                                        
                                        
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithProjectAuditChangeNotification(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithProjectAuditChangeNotification(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Analysis Decision: Finding Suppressed");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Analysis Decision: Finding Suppressed
                                        
                    --------------------------------------------------------------------------------
                                        
                    Analysis Type:  Project Analysis
                                        
                    Analysis State:    FALSE_POSITIVE
                    Suppressed:        true
                    Vulnerability ID:  INT-001
                    Vulnerability URL: /vulnerability/?source=INTERNAL&vulnId=INT-001
                    Severity:          MEDIUM
                    Source:            INTERNAL
                                        
                    Component:         componentName : componentVersion
                    Component URL:     /component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                    Project:           [projectName : projectVersion]
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                                        
                    --------------------------------------------------------------------------------
                                        
                                        
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
    }

    @Override
    public void testInformWithEscapedData(WireMockRuntimeInfo wmRuntimeInfo) {
        super.testInformWithEscapedData(wmRuntimeInfo);

        assertThat(greenMail.getReceivedMessages()).satisfiesExactly(message -> {
            assertThat(message.getSubject()).isEqualTo("[Dependency-Track] Notification Test");
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);
            assertThat((String) content.getBodyPart(0).getContent()).isEqualToIgnoringNewLines("""
                    Notification Test
                                        
                    --------------------------------------------------------------------------------
                                        
                    Level:     ERROR
                    Scope:     SYSTEM
                    Group:     ANALYZER
                                        
                    --------------------------------------------------------------------------------
                                        
                    ! " § $ % & / ( ) = ? \\ ' * Ö Ü Ä ®️
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
        
    }

    @Override
    public void testInformWithTemplateInclude(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.NOTIFICATION_TEST)
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC));

        final JsonObject config = Json.createObjectBuilder(createConfig(wmRuntimeInfo))
                .add(Publisher.CONFIG_TEMPLATE_KEY, "{% include '/etc/passwd' %}")
                .build();

        // NB: In contrast to other publishers, SendMailPublisher catches and logs
        // failures during template evaluation. Instead of expecting an exception
        // being thrown, we verify that no email was sent.
        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(PublishContext.from(notification), notification, config));

        assertThat(greenMail.getReceivedMessages()).isEmpty();
    }

    @Override
    JsonObjectBuilder extraConfig(WireMockRuntimeInfo wmRuntimeInfo) {
        return super.extraConfig(wmRuntimeInfo)
                .add(Publisher.CONFIG_DESTINATION, "username@example.com");
    }

    private static JsonObject configWithDestination(final String destination) {
        return Json.createObjectBuilder().add("destination", destination).build();
    }

    @Test
    void testSingleDestination() {
        JsonObject config = configWithDestination("john@doe.com");
        Assertions.assertArrayEquals(new String[]{"john@doe.com"}, SendMailPublisher.parseDestination(config));
    }


    @Test
    void testMultipleDestinations() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        Assertions.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org"},
                SendMailPublisher.parseDestination(config));
    }

    @Test
    void testNullDestination() {
        Assertions.assertArrayEquals(null, SendMailPublisher.parseDestination(Json.createObjectBuilder().build()));
    }

    @Test
    void testEmptyDestinations() {
        JsonObject config = configWithDestination("");
        Assertions.assertArrayEquals(null, SendMailPublisher.parseDestination(config));
    }

    @Test
    void testSingleTeamAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        managedUser.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setLdapUsers(ldapUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testMultipleTeamsAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser1 = new ManagedUser();
        managedUser1.setUsername("ManagedUserTest");
        managedUser1.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers1 = new ArrayList<>();
        managedUsers1.add(managedUser1);

        LdapUser ldapUser1 = new LdapUser();
        ldapUser1.setUsername("ldapUserTest");
        ldapUser1.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers1 = new ArrayList<>();
        ldapUsers1.add(ldapUser1);

        OidcUser oidcUser1 = new OidcUser();
        oidcUser1.setUsername("oidcUserTest");
        oidcUser1.setEmail("oidcUser@Test.com");
        List<OidcUser> oidcUsers1 = new ArrayList<>();
        oidcUsers1.add(oidcUser1);

        List<Team> teams = new ArrayList<>();
        Team team1 = new Team();
        team1.setManagedUsers(managedUsers1);
        team1.setLdapUsers(ldapUsers1);
        team1.setOidcUsers(oidcUsers1);
        teams.add(team1);

        ManagedUser managedUser2 = new ManagedUser();
        managedUser2.setUsername("ManagedUserTest");
        managedUser2.setEmail("anotherManagedUser@Test.com");
        List<ManagedUser> managedUsers2 = new ArrayList<>();
        managedUsers2.add(managedUser2);

        LdapUser ldapUser2 = new LdapUser();
        ldapUser2.setUsername("ldapUserTest");
        ldapUser2.setEmail("anotherLdapUser@Test.com");
        List<LdapUser> ldapUsers2 = new ArrayList<>();
        ldapUsers2.add(ldapUser2);

        OidcUser oidcUser2 = new OidcUser();
        oidcUser2.setUsername("oidcUserTest");
        oidcUser2.setEmail("anotherOidcUser@Test.com");
        List<OidcUser> oidcUsers2 = new ArrayList<>();
        oidcUsers2.add(oidcUser2);

        Team team2 = new Team();
        team2.setManagedUsers(managedUsers2);
        team2.setLdapUsers(ldapUsers2);
        team2.setOidcUsers(oidcUsers2);
        teams.add(team2);

        Assertions.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com", "anotherManagedUser@Test.com",
                "anotherLdapUser@Test.com", "anotherOidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testDuplicateTeamAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser1 = new ManagedUser();
        managedUser1.setUsername("ManagedUserTest");
        managedUser1.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers1 = new ArrayList<>();
        managedUsers1.add(managedUser1);

        LdapUser ldapUser1 = new LdapUser();
        ldapUser1.setUsername("ldapUserTest");
        ldapUser1.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers1 = new ArrayList<>();
        ldapUsers1.add(ldapUser1);

        OidcUser oidcUser1 = new OidcUser();
        oidcUser1.setUsername("oidcUserTest");
        oidcUser1.setEmail("oidcUser@Test.com");
        List<OidcUser> oidcUsers1 = new ArrayList<>();
        oidcUsers1.add(oidcUser1);

        List<Team> teams = new ArrayList<>();
        Team team1 = new Team();
        team1.setManagedUsers(managedUsers1);
        team1.setLdapUsers(ldapUsers1);
        team1.setOidcUsers(oidcUsers1);
        teams.add(team1);

        ManagedUser managedUser2 = new ManagedUser();
        managedUser2.setUsername("ManagedUserTest");
        managedUser2.setEmail("anotherManagedUser@Test.com");
        List<ManagedUser> managedUsers2 = new ArrayList<>();
        managedUsers2.add(managedUser2);

        LdapUser ldapUser2 = new LdapUser();
        ldapUser2.setUsername("ldapUserTest");
        ldapUser2.setEmail("anotherLdapUser@Test.com");
        List<LdapUser> ldapUsers2 = new ArrayList<>();
        ldapUsers2.add(ldapUser2);

        OidcUser oidcUser2 = new OidcUser();
        oidcUser2.setUsername("oidcUserTest");
        oidcUser2.setEmail("anotherOidcUser@Test.com");
        List<OidcUser> oidcUsers2 = new ArrayList<>();
        oidcUsers2.add(oidcUser2);
        oidcUsers2.add(oidcUser1);

        Team team2 = new Team();
        team2.setManagedUsers(managedUsers2);
        team2.setLdapUsers(ldapUsers2);
        team2.setOidcUsers(oidcUsers2);
        teams.add(team2);

        Assertions.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com", "anotherManagedUser@Test.com",
                "anotherLdapUser@Test.com", "anotherOidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testDuplicateUserAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        managedUser.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setLdapUsers(ldapUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testEmptyTeamAsDestination() {
        JsonObject config = configWithDestination("");
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        teams.add(team);
        Assertions.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testEmptyTeamsAsDestination() {
        JsonObject config = configWithDestination("");
        List<Team> teams = new ArrayList<>();
        Assertions.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testEmptyUserEmailsAsDestination() {
        JsonObject config = configWithDestination("");
        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setLdapUsers(ldapUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);

        Assertions.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testConfigDestinationAndTeamAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        managedUser.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        oidcUser.setEmail("john@doe.com");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setLdapUsers(ldapUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "ldapUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testNullConfigDestinationAndTeamsDestination() {
        JsonObject config = Json.createObjectBuilder().build();
        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        managedUser.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        oidcUser.setEmail("john@doe.com");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setLdapUsers(ldapUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "john@doe.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testEmptyManagedUsersAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setLdapUsers(ldapUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testEmptyLdapUsersAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        managedUser.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        OidcUser oidcUser = new OidcUser();
        oidcUser.setUsername("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");
        List<OidcUser> oidcUsers = new ArrayList<>();
        oidcUsers.add(oidcUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setOidcUsers(oidcUsers);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    void testEmptyOidcUsersAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        ManagedUser managedUser = new ManagedUser();
        managedUser.setUsername("ManagedUserTest");
        managedUser.setEmail("managedUser@Test.com");
        List<ManagedUser> managedUsers = new ArrayList<>();
        managedUsers.add(managedUser);

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUsername("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");
        List<LdapUser> ldapUsers = new ArrayList<>();
        ldapUsers.add(ldapUser);

        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        team.setManagedUsers(managedUsers);
        team.setLdapUsers(ldapUsers);
        teams.add(team);

        Assertions.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "ldapUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }
}
