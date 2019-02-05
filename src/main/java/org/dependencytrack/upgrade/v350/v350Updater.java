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
package org.dependencytrack.upgrade.v350;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import org.apache.commons.lang.StringUtils;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import java.sql.Connection;
import java.sql.SQLException;

public class v350Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v350Updater.class);


    public String getSchemaVersion() {
        return "3.5.0";
    }

    public void executeUpgrade(AlpineQueryManager aqm, Connection connection) throws SQLException {
        LOGGER.info("Validating project names");
        try (QueryManager qm = new QueryManager(aqm.getPersistenceManager())) {
            for (Project project: qm.getAllProjects()) {
                if (null == StringUtils.trimToNull(project.getName())) {
                    project.setName("(Undefined)");
                    qm.persist(project);
                }
                if (project.getVersion() != null && StringUtils.trimToNull(project.getVersion()) == null) {
                    project.setVersion(null);
                    qm.persist(project);
                }
            }
        }
    }

}