package org.dependencytrack.notification.publisher;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import alpine.security.crypto.DataEncryption;
import com.icegreen.greenmail.junit4.GreenMailRule;
import com.icegreen.greenmail.util.ServerSetup;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
import java.util.ArrayList;
import java.util.List;

import static com.icegreen.greenmail.configuration.GreenMailConfiguration.aConfig;
import static org.assertj.core.api.Assertions.assertThat;
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
                                        
                    Project:           pkg:maven/org.acme/projectName@projectVersion
                    Project URL:       /projects/?uuid=c9c9539a-e381-4b36-ac52-6a7ab83b2c95
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
                    Project:           pkg:maven/org.acme/projectName@projectVersion
                    Description:       projectDescription
                    Project URL:       /projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                                        
                    --------------------------------------------------------------------------------
                                        
                                        
                                        
                    --------------------------------------------------------------------------------
                                        
                    1970-01-01T18:31:06.000000666
                    """);
        });
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
        Assert.assertArrayEquals(new String[]{"john@doe.com"}, SendMailPublisher.parseDestination(config));
    }


    @Test
    public void testMultipleDestinations() {
        JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
        Assert.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org"},
                SendMailPublisher.parseDestination(config));
    }

    @Test
    public void testNullDestination() {
        Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(Json.createObjectBuilder().build()));
    }

    @Test
    public void testEmptyDestinations() {
        JsonObject config = configWithDestination("");
        Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config));
    }

    @Test
    public void testSingleTeamAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testMultipleTeamsAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com", "anotherManagedUser@Test.com",
                "anotherLdapUser@Test.com", "anotherOidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testDuplicateTeamAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com", "anotherManagedUser@Test.com",
                "anotherLdapUser@Test.com", "anotherOidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testDuplicateUserAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testEmptyTeamAsDestination() {
        JsonObject config = configWithDestination("");
        List<Team> teams = new ArrayList<>();
        Team team = new Team();
        teams.add(team);
        Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testEmptyTeamsAsDestination() {
        JsonObject config = configWithDestination("");
        List<Team> teams = new ArrayList<>();
        Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testEmptyUserEmailsAsDestination() {
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

        Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testConfigDestinationAndTeamAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "ldapUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testNullConfigDestinationAndTeamsDestination() {
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

        Assert.assertArrayEquals(new String[]{"managedUser@Test.com", "ldapUser@Test.com", "john@doe.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testEmptyManagedUsersAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testEmptyLdapUsersAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }

    @Test
    public void testEmptyOidcUsersAsDestination() {
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

        Assert.assertArrayEquals(new String[]{"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "ldapUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
    }
}
