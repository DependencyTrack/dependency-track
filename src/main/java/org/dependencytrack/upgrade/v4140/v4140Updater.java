package org.dependencytrack.upgrade.v4140;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import org.dependencytrack.upgrade.v480.v480Updater;

import java.sql.Connection;
import java.sql.Statement;

public class v4140Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v480Updater.class);
    @Override
    public String getSchemaVersion() {
        return "4.14.0";
    }

    @Override
    public void executeUpgrade(AlpineQueryManager alpineQueryManager, Connection connection) throws Exception {
        LOGGER.info("Updating component table for scope column");
        try (Statement statement= connection.createStatement()){
            statement.execute("ALTER TABLE \"COMPONENT\" ADD \"SCOPE\" VARCHAR(255)");
        }
    }
}
