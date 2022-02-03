package org.dependencytrack.upgrade.v440;

import alpine.logging.Logger;
import alpine.model.Permission;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import org.dependencytrack.auth.Permissions;

import java.sql.Connection;

public class v440Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v440Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.4.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        LOGGER.info("Creating VIEW_VULNERABILITY permission");
        final Permission viewVulnPermission = qm.createPermission(Permissions.VIEW_VULNERABILITY.name(), Permissions.VIEW_VULNERABILITY.getDescription());

        LOGGER.info("Granting VIEW_VULNERABILITY permission to managed users with VULNERABILITY_ANALYSIS permission");
        for (var user : qm.getManagedUsers()) {
            if (user.getPermissions().stream().map(Permission::getName).anyMatch(Permissions.VULNERABILITY_ANALYSIS.name()::equals)) {
                LOGGER.info("Granting VIEW_VULNERABILITY permission to managed user " + user.getUsername());
                user.getPermissions().add(viewVulnPermission);
                qm.persist(user);
            }
        }

        LOGGER.info("Granting VIEW_VULNERABILITY permission to LDAP users with VULNERABILITY_ANALYSIS permission");
        for (var user : qm.getLdapUsers()) {
            if (user.getPermissions().stream().map(Permission::getName).anyMatch(Permissions.VULNERABILITY_ANALYSIS.name()::equals)) {
                LOGGER.info("Granting VIEW_VULNERABILITY permission to LDAP user " + user.getUsername());
                user.getPermissions().add(viewVulnPermission);
                qm.persist(user);
            }
        }

        LOGGER.info("Granting VIEW_VULNERABILITY permission to OIDC users with VULNERABILITY_ANALYSIS permission");
        for (var user : qm.getOidcUsers()) {
            if (user.getPermissions().stream().map(Permission::getName).anyMatch(Permissions.VULNERABILITY_ANALYSIS.name()::equals)) {
                LOGGER.info("Granting VIEW_VULNERABILITY permission to OIDC user " + user.getUsername());
                user.getPermissions().add(viewVulnPermission);
                qm.persist(user);
            }
        }

        LOGGER.info("Granting VIEW_VULNERABILITY permission to teams with VULNERABILITY_ANALYSIS permission");
        for (var team : qm.getTeams()) {
            if (team.getPermissions().stream().map(Permission::getName).anyMatch(Permissions.VULNERABILITY_ANALYSIS.name()::equals)) {
                LOGGER.info("Granting VIEW_VULNERABILITY permission to team " + team.getName());
                team.getPermissions().add(viewVulnPermission);
                qm.persist(team);
            }
        }
    }

}
