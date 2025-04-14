package org.dependencytrack.notification.publisher;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import alpine.server.auth.PasswordService;
import com.icegreen.greenmail.junit4.GreenMailRule;
import com.icegreen.greenmail.util.ServerSetup;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
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

public class SendMailPublisherTest extends AbstractPublisherTest<SendMailPublisher> {

    // Hashing is expensive. Do it once and re-use across tests as much as possible.
    protected static final String TEST_USER_PASSWORD_HASH = new String(PasswordService.createHash("testuser".toCharArray()));

    @Rule
    public final GreenMailRule greenMail = new GreenMailRule(ServerSetup.SMTP.dynamicPort())
            .withConfiguration(aConfig().
                    withUser("username", "password"));

    public SendMailPublisherTest() {
        super(DefaultNotificationPublishers.EMAIL, new SendMailPublisher());
    }

    @Before
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
    public void testInformWithBomConsumedNotification() {
        super.testInformWithBomConsumedNotification();

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
    public void testInformWithBomProcessingFailedNotification() {
        super.testInformWithBomProcessingFailedNotification();

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
    public void testInformWithBomValidationFailedNotification() {
        super.testInformWithBomValidationFailedNotification();

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
    public void testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject() {
        super.testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject();

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
    public void testInformWithDataSourceMirroringNotification() {
        super.testInformWithDataSourceMirroringNotification();

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
    public void testInformWithNewVulnerabilityNotification() {
        super.testInformWithNewVulnerabilityNotification();

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
    public void testPublishWithScheduledNewVulnerabilitiesNotification() {
        super.testPublishWithScheduledNewVulnerabilitiesNotification();

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
    public void testPublishWithScheduledNewPolicyViolationsNotification() {
        super.testPublishWithScheduledNewPolicyViolationsNotification();

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
    public void testInformWithNewVulnerableDependencyNotification() {
        super.testInformWithNewVulnerableDependencyNotification();

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
    public void testInformWithProjectAuditChangeNotification() {
        super.testInformWithProjectAuditChangeNotification();

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
    public void testInformWithEscapedData() {
        super.testInformWithEscapedData();

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
    public void testInformWithTemplateInclude() throws Exception {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.NOTIFICATION_TEST)
                .level(NotificationLevel.ERROR)
                .timestamp(LocalDateTime.ofEpochSecond(66666, 666, ZoneOffset.UTC));

        final JsonObject config = Json.createObjectBuilder(createConfig())
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
    JsonObjectBuilder extraConfig() {
        return super.extraConfig()
                .add(Publisher.CONFIG_DESTINATION, "username@example.com");
    }

    private static JsonObject configWithDestination(final String destination) {
        return Json.createObjectBuilder().add("destination", destination).build();
    }

    @Test
    public void testSingleDestination() {
        JsonObject config = configWithDestination("john@doe.com");
        assertThat(SendMailPublisher.getDestinations(config, -1L)).containsOnly("john@doe.com");
    }


    @Test
    public void testMultipleDestinations() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        assertThat(SendMailPublisher.getDestinations(config, -1L))
                .containsExactlyInAnyOrder("john@doe.com", "steve@jobs.org");
    }

    @Test
    public void testNullDestination() {
        assertThat(SendMailPublisher.getDestinations(Json.createObjectBuilder().build(), -1L)).isNull();
    }

    @Test
    public void testEmptyDestinations() {
        JsonObject config = configWithDestination("");
        assertThat(SendMailPublisher.getDestinations(config, -1L)).isNull();
    }

    @Test
    public void testSingleTeamAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);
        managedUser.setEmail("managedUser@Test.com");

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(ldapUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder("managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com");
    }

    @Test
    public void testMultipleTeamsAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser1 = qm.createManagedUser("ManagedUserTest1", TEST_USER_PASSWORD_HASH);
        managedUser1.setEmail("managedUser@Test.com");

        LdapUser ldapUser1 = qm.createLdapUser("ldapUserTest1");
        ldapUser1.setEmail("ldapUser@Test.com");

        OidcUser oidcUser1 = qm.createOidcUser("oidcUserTest1");
        oidcUser1.setEmail("oidcUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team1 = qm.createTeam("testTeam1");
        qm.addUserToTeam(managedUser1, team1);
        qm.addUserToTeam(ldapUser1, team1);
        qm.addUserToTeam(oidcUser1, team1);
        teams.add(team1);

        ManagedUser managedUser2 = qm.createManagedUser("ManagedUserTest2", TEST_USER_PASSWORD_HASH);
        managedUser2.setEmail("anotherManagedUser@Test.com");

        LdapUser ldapUser2 = qm.createLdapUser("ldapUserTest2");
        ldapUser2.setEmail("anotherLdapUser@Test.com");

        OidcUser oidcUser2 = qm.createOidcUser("oidcUserTest2");
        oidcUser2.setEmail("anotherOidcUser@Test.com");

        Team team2 = qm.createTeam("testTeam2");
        qm.addUserToTeam(managedUser2, team2);
        qm.addUserToTeam(ldapUser2, team2);
        qm.addUserToTeam(oidcUser2, team2);
        teams.add(team2);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder(
                        "anotherLdapUser@Test.com",
                        "anotherManagedUser@Test.com",
                        "anotherOidcUser@Test.com",
                        "ldapUser@Test.com",
                        "managedUser@Test.com",
                        "oidcUser@Test.com");
    }

    @Test
    public void testDuplicateTeamAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser1 = qm.createManagedUser("ManagedUserTest1", TEST_USER_PASSWORD_HASH);
        managedUser1.setEmail("managedUser@Test.com");

        LdapUser ldapUser1 = qm.createLdapUser("ldapUserTest1");
        ldapUser1.setEmail("ldapUser@Test.com");

        OidcUser oidcUser1 = qm.createOidcUser("oidcUserTest1");
        oidcUser1.setEmail("oidcUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team1 = qm.createTeam("testTeam1");
        qm.addUserToTeam(managedUser1, team1);
        qm.addUserToTeam(ldapUser1, team1);
        qm.addUserToTeam(oidcUser1, team1);
        teams.add(team1);

        ManagedUser managedUser2 = qm.createManagedUser("ManagedUserTest2", TEST_USER_PASSWORD_HASH);
        managedUser2.setEmail("anotherManagedUser@Test.com");

        LdapUser ldapUser2 = qm.createLdapUser("ldapUserTest2");
        ldapUser2.setEmail("anotherLdapUser@Test.com");

        OidcUser oidcUser2 = qm.createOidcUser("oidcUserTest2");
        oidcUser2.setEmail("anotherOidcUser@Test.com");

        Team team2 = qm.createTeam("testTeam2");
        qm.addUserToTeam(managedUser2, team2);
        qm.addUserToTeam(ldapUser2, team2);
        qm.addUserToTeam(oidcUser2, team2);
        qm.addUserToTeam(oidcUser1, team2);
        teams.add(team2);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder(
                        "anotherLdapUser@Test.com",
                        "anotherManagedUser@Test.com",
                        "anotherOidcUser@Test.com",
                        "ldapUser@Test.com",
                        "managedUser@Test.com",
                        "oidcUser@Test.com");
    }

    @Test
    public void testDuplicateUserAsDestination() {
        JsonObject config = configWithDestination("");

        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);
        managedUser.setEmail("managedUser@Test.com");

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(ldapUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder("managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com");
    }

    @Test
    public void testEmptyTeamAsDestination() {
        JsonObject config = configWithDestination("");
        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        teams.add(team);
        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);
        assertThat(SendMailPublisher.getDestinations(config, rule.getId())).isNull();
    }

    @Test
    public void testEmptyTeamsAsDestination() {
        JsonObject config = configWithDestination("");
        List<Team> teams = new ArrayList<>();
        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);
        assertThat(SendMailPublisher.getDestinations(config, rule.getId())).isNull();
    }

    @Test
    public void testEmptyUserEmailsAsDestination() {
        JsonObject config = configWithDestination("");
        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(ldapUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId())).isNull();
    }

    @Test
    public void testConfigDestinationAndTeamAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);
        managedUser.setEmail("managedUser@Test.com");

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");
        oidcUser.setEmail("john@doe.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(ldapUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder(
                        "john@doe.com",
                        "ldapUser@Test.com",
                        "managedUser@Test.com",
                        "steve@jobs.org");
    }

    @Test
    public void testNullConfigDestinationAndTeamsDestination() {
        JsonObject config = Json.createObjectBuilder().build();
        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);
        managedUser.setEmail("managedUser@Test.com");

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");
        oidcUser.setEmail("john@doe.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(ldapUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder("managedUser@Test.com", "ldapUser@Test.com", "john@doe.com");
    }

    @Test
    public void testEmptyManagedUsersAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(ldapUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder(
                        "john@doe.com",
                        "ldapUser@Test.com",
                        "oidcUser@Test.com",
                        "steve@jobs.org");
    }

    @Test
    public void testEmptyLdapUsersAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);
        managedUser.setEmail("managedUser@Test.com");

        OidcUser oidcUser = qm.createOidcUser("oidcUserTest");
        oidcUser.setEmail("oidcUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(oidcUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder(
                        "john@doe.com",
                        "managedUser@Test.com",
                        "oidcUser@Test.com",
                        "steve@jobs.org");
    }

    @Test
    public void testEmptyOidcUsersAsDestination() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        ManagedUser managedUser = qm.createManagedUser("ManagedUserTest", TEST_USER_PASSWORD_HASH);
        managedUser.setEmail("managedUser@Test.com");

        LdapUser ldapUser = qm.createLdapUser("ldapUserTest");
        ldapUser.setEmail("ldapUser@Test.com");

        List<Team> teams = new ArrayList<>();
        Team team = qm.createTeam("testTeam");
        qm.addUserToTeam(managedUser, team);
        qm.addUserToTeam(ldapUser, team);
        teams.add(team);

        NotificationRule rule = createNotificationRule();
        rule.setTeams(teams);

        assertThat(SendMailPublisher.getDestinations(config, rule.getId()))
                .containsExactlyInAnyOrder(
                        "john@doe.com",
                        "ldapUser@Test.com",
                        "managedUser@Test.com",
                        "steve@jobs.org");
    }

    private NotificationRule createNotificationRule() {
        final NotificationPublisher publisher = qm.createNotificationPublisher(
                DefaultNotificationPublishers.EMAIL.getPublisherName(),
                DefaultNotificationPublishers.EMAIL.getPublisherDescription(),
                DefaultNotificationPublishers.EMAIL.getPublisherClass(),
                "template",
                DefaultNotificationPublishers.EMAIL.getTemplateMimeType(),
                DefaultNotificationPublishers.EMAIL.isDefaultPublisher());

        return qm.createNotificationRule(
                "testRule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
    }

}
