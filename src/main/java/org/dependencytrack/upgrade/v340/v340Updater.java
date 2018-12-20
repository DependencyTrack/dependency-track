/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v340;

import alpine.event.framework.Event;
import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.search.IndexManager;
import java.sql.Connection;
import java.sql.SQLException;

public class v340Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v340Updater.class);


    public String getSchemaVersion() {
        return "3.4.0";
    }

    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws SQLException {
        LOGGER.info("Recreating table PROJECT_PROPERTY");
        DbUtil.dropTable(connection, "PROJECT_PROPERTY"); // Will be dynamically recreated

        LOGGER.info("Deleting search engine indices");
        IndexManager.deleteIndexDirectory(IndexManager.IndexType.LICENSE);
        IndexManager.deleteIndexDirectory(IndexManager.IndexType.PROJECT);
        IndexManager.deleteIndexDirectory(IndexManager.IndexType.COMPONENT);
        IndexManager.deleteIndexDirectory(IndexManager.IndexType.VULNERABILITY);

        LOGGER.info("Dispatching events to reindex all objects"); //todo change this to check for empty directory and reindex - default object generator?
        Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, License.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, Project.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, Component.class));
        Event.dispatch(new IndexEvent(IndexEvent.Action.REINDEX, Vulnerability.class));
    }

}