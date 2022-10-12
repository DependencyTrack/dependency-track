package org.dependencytrack.notification.publisher;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Team;
import org.junit.Assert;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import java.util.ArrayList;
import java.util.List;

public class SendMailPublisherTest {
  private static JsonObject configWithDestination(final String destination) {
    return Json.createObjectBuilder().add("destination", destination).build();
  }


  @Test
  public void testSingleDestination() {
    JsonObject config = configWithDestination("john@doe.com");
    Assert.assertArrayEquals(new String[] { "john@doe.com" }, SendMailPublisher.parseDestination(config));
  }


  @Test
  public void testMultipleDestinations() {
    JsonObject config = configWithDestination("john@doe.com,steve@jobs.org");
    Assert.assertArrayEquals(new String[] { "john@doe.com", "steve@jobs.org" },
                             SendMailPublisher.parseDestination(config));
  }


  @Test
  public void testEmptyDestinations() {
    JsonObject config = configWithDestination("");
    Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config));
  }

  @Test
  public void testSingleTeamAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testMultipleTeamsAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com", "anotherManagedUser@Test.com",
            "anotherLdapUser@Test.com", "anotherOidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testDuplicateTeamAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com", "anotherManagedUser@Test.com",
            "anotherLdapUser@Test.com", "anotherOidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testDuplicateUserAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"managedUser@Test.com", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testEmptyTeamAsDestination(){
    JsonObject config = configWithDestination("");
    List<Team> teams = new ArrayList<>();
    Team team = new Team();
    teams.add(team);
    Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testEmptyTeamsAsDestination(){
    JsonObject config = configWithDestination("");
    List<Team> teams = new ArrayList<>();
    Assert.assertArrayEquals(null, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testEmptyUserEmailsAsDestination(){
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
  public void testConfigDestinationAndTeamAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "ldapUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testEmptyManagedUsersAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"john@doe.com", "steve@jobs.org", "ldapUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }

  @Test
  public void testEmptyLdapUsersAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "oidcUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }
  @Test
  public void testEmptyOidcUsersAsDestination(){
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

    Assert.assertArrayEquals(new String[] {"john@doe.com", "steve@jobs.org", "managedUser@Test.com", "ldapUser@Test.com"}, SendMailPublisher.parseDestination(config, teams));
  }
}
