/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v370;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class v370Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v370Updater.class);
    private static final String STMT_1 = "UPDATE \"COMPONENT\" SET \"INTERNAL\" = FALSE WHERE \"INTERNAL\" IS NULL";
    private static final String STMT_1_ALT = "UPDATE \"COMPONENT\" SET \"INTERNAL\" = 0 WHERE \"INTERNAL\" IS NULL";
    private static final String STMT_2 = "SELECT \"ID\" FROM \"PERMISSION\" WHERE \"NAME\" = 'SCAN_UPLOAD'";
    private static final String STMT_3 = "DELETE FROM \"TEAMS_PERMISSIONS\" WHERE \"PERMISSION_ID\" = %d";
    private static final String STMT_4 = "DELETE FROM \"LDAPUSERS_PERMISSIONS\" WHERE \"PERMISSION_ID\" = %d";
    private static final String STMT_5 = "DELETE FROM \"MANAGEDUSERS_PERMISSIONS\" WHERE \"PERMISSION_ID\" = %d";
    private static final String STMT_6 = "DELETE FROM \"PERMISSION\" WHERE \"ID\" = %d";
    private static final String STMT_7 = "DELETE FROM \"SCANS_COMPONENTS\"";
    private static final String STMT_8 = "UPDATE \"PROJECT\" SET \"LAST_SCAN_IMPORTED\" = NULL";
    private static final String STMT_9 = "DELETE FROM \"SCAN\"";
    private static final String STMT_10 = "DELETE FROM \"CONFIGPROPERTY\" WHERE \"GROUPNAME\" = 'artifact' AND \"PROPERTYNAME\" = 'dependencycheck.enabled'";

    @Override
    public String getSchemaVersion() {
        return "3.7.0";
    }

    
}
