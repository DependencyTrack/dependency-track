package org.dependencytrack.upgrade.v440;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.upgrade.UpgradeException;
import org.dependencytrack.auth.Permissions;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class v440Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v440Updater.class);
    private static final String STMT_1 = "INSERT INTO \"PERMISSION\" (\"NAME\", \"DESCRIPTION\") VALUES (?, ?)";
    private static final String STMT_2 = "SELECT \"ID\" FROM \"PERMISSION\" WHERE \"NAME\" = ? LIMIT 1";
    private static final String STMT_3 = "SELECT \"u\".\"ID\" FROM \"MANAGEDUSER\" AS \"u\" INNER JOIN \"MANAGEDUSERS_PERMISSIONS\" AS \"up\" ON \"up\".\"MANAGEDUSER_ID\" = \"u\".\"ID\" WHERE \"up\".\"PERMISSION_ID\" = %d";
    private static final String STMT_4 = "INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_5 = "SELECT \"u\".\"ID\" FROM \"LDAPUSER\" AS \"u\" INNER JOIN \"LDAPUSERS_PERMISSIONS\" AS \"up\" ON \"up\".\"LDAPUSER_ID\" = \"u\".\"ID\" WHERE \"up\".\"PERMISSION_ID\" = %d";
    private static final String STMT_6 = "INSERT INTO \"LDAPUSERS_PERMISSIONS\" (\"LDAPUSER_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_7 = "SELECT \"u\".\"ID\" FROM \"OIDCUSER\" AS \"u\" INNER JOIN \"OIDCUSERS_PERMISSIONS\" AS \"up\" ON \"up\".\"OIDCUSER_ID\" = \"u\".\"ID\" WHERE \"up\".\"PERMISSION_ID\" = %d";
    private static final String STMT_8 = "INSERT INTO \"OIDCUSERS_PERMISSIONS\" (\"OIDCUSER_ID\", \"PERMISSION_ID\") VALUES (?, ?)";
    private static final String STMT_9 = "SELECT \"t\".\"ID\" FROM \"TEAM\" AS \"t\" INNER JOIN \"TEAMS_PERMISSIONS\" AS \"tp\" ON \"tp\".\"TEAM_ID\" = \"t\".\"ID\" WHERE \"tp\".\"PERMISSION_ID\" = %d";
    private static final String STMT_10 = "INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (?, ?)";

    @Override
    public String getSchemaVersion() {
        return "4.4.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        LOGGER.info("Creating VIEW_VULNERABILITY permission");
        PreparedStatement ps = connection.prepareStatement(STMT_1);
        ps.setString(1, Permissions.VIEW_VULNERABILITY.name());
        ps.setString(2, Permissions.VIEW_VULNERABILITY.getDescription());
        ps.executeUpdate();

        final long viewVulnPermissionId = getPermissionId(connection, Permissions.VIEW_VULNERABILITY);
        final long vulnAnalysisPermissionId = getPermissionId(connection, Permissions.VULNERABILITY_ANALYSIS);

        LOGGER.info("Granting VIEW_VULNERABILITY permission to managed users with VULNERABILITY_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_3, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_4);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Granting VIEW_VULNERABILITY permission to LDAP users with VULNERABILITY_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_5, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_6);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Granting VIEW_VULNERABILITY permission to OIDC users with VULNERABILITY_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_7, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_8);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }

        LOGGER.info("Granting VIEW_VULNERABILITY permission to teams with VULNERABILITY_ANALYSIS permission");
        try (final Statement stmt = connection.createStatement()) {
            final ResultSet rs = stmt.executeQuery(String.format(STMT_9, vulnAnalysisPermissionId));
            while (rs.next()) {
                ps = connection.prepareStatement(STMT_10);
                ps.setLong(1, rs.getLong(1));
                ps.setLong(2, viewVulnPermissionId);
                ps.executeUpdate();
            }
        }
    }

    private long getPermissionId(final Connection connection, final Permissions permission) throws SQLException, UpgradeException {
        final PreparedStatement ps = connection.prepareStatement(STMT_2);
        ps.setString(1, permission.name());

        final ResultSet rs = ps.executeQuery();
        if (!rs.next()) {
            throw new UpgradeException("Unable to determine ID of permission " + permission.name());
        }

        return rs.getLong(1);
    }

}
