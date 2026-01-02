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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v4123;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.Classifier;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.StringJoiner;

public class v4123Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4123Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.12.3";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        maybeRecreateClassifierCheckConstraints(connection);
    }

    private void maybeRecreateClassifierCheckConstraints(final Connection connection) throws SQLException {
        if (DbUtil.isH2()) {
            maybeRecreateClassifierCheckConstraintsForH2(connection);
        } else if (DbUtil.isMssql()) {
            maybeRecreateClassifierCheckConstraintsForMssql(connection);
        } else if (DbUtil.isMysql()) {
            // MySQL < 8 does not support check constraints.
            // Since we never officially moved MySQL support past 5.7,
            // there's nothing to do here.
        } else if (DbUtil.isPostgreSQL()) {
            maybeRecreateClassifierCheckConstraintsForPostgres(connection);
        } else {
            throw new IllegalStateException(
                    "Unsupported database: " + connection.getMetaData().getDatabaseProductName());
        }
    }

    private record ClassifierConstraint(String tableName, String columnName, String name, String definition) {

        static ClassifierConstraint of(final ResultSet rs) throws SQLException {
            return new ClassifierConstraint(
                    rs.getString("TABLE_NAME"),
                    rs.getString("COLUMN_NAME"),
                    rs.getString("NAME"),
                    rs.getString("DEFINITION"));
        }

        private ClassifierConstraint withoutName() {
            return new ClassifierConstraint(tableName, columnName, null, definition);
        }

        private boolean isCurrent() {
            final var missingClassifiers = new HashSet<Classifier>();
            for (final Classifier classifier : Classifier.values()) {
                if (!definition.contains(classifier.name())) {
                    missingClassifiers.add(classifier);
                }
            }

            if (!missingClassifiers.isEmpty()) {
                LOGGER.info("Classifiers %s not found in check constraint %s; Current definition: %s".formatted(
                        missingClassifiers, name, definition));
                return false;
            }

            return true;
        }

    }

    private void maybeRecreateClassifierCheckConstraintsForH2(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            statement.execute("""
                    SELECT CC.CONSTRAINT_NAME AS NAME
                         , CC.CHECK_CLAUSE AS DEFINITION
                         , CCU.TABLE_NAME AS TABLE_NAME
                         , CCU.COLUMN_NAME AS COLUMN_NAME
                      FROM INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE AS CCU
                     INNER JOIN INFORMATION_SCHEMA.CHECK_CONSTRAINTS AS CC
                        ON CC.CONSTRAINT_SCHEMA = CCU.CONSTRAINT_SCHEMA
                       AND CC.CONSTRAINT_NAME = CCU.CONSTRAINT_NAME
                     WHERE CCU.TABLE_NAME IN ('COMPONENT', 'PROJECT')
                       AND CCU.COLUMN_NAME = 'CLASSIFIER';
                    """);

            final var constraints = new ArrayList<ClassifierConstraint>();

            try (final ResultSet rs = statement.getResultSet()) {
                while (rs.next()) {
                    constraints.add(ClassifierConstraint.of(rs));
                }
            }

            final var constraintsSeen = new HashSet<ClassifierConstraint>();
            for (final ClassifierConstraint constraint : constraints) {
                if (!constraintsSeen.add(constraint.withoutName())) {
                    // DataNucleus may have created duplicate constraints before.
                    // https://github.com/datanucleus/datanucleus-rdbms/issues/500
                    LOGGER.warn("Detected duplicate constraint %s on table %s; Dropping".formatted(
                            constraint.name(), constraint.tableName()));

                    statement.execute("ALTER TABLE \"%s\" DROP CONSTRAINT \"%s\"".formatted(
                            constraint.tableName(), constraint.name()));
                    continue;
                }

                if (constraint.isCurrent()) {
                    LOGGER.info("Constraint %s on table %s is already current; Will not re-create".formatted(
                            constraint.name(), constraint.tableName()));
                    continue;
                }

                LOGGER.info("Constraint %s on table %s is outdated; Recreating".formatted(
                        constraint.name(), constraint.tableName()));

                statement.execute("ALTER TABLE \"%s\" DROP CONSTRAINT \"%s\"".formatted(
                        constraint.tableName(), constraint.name()));

                statement.execute("ALTER TABLE \"%s\" ADD CONSTRAINT \"%s\" CHECK %s".formatted(
                        constraint.tableName(), constraint.name(), classifierCheckConstraint()));
            }
        }
    }

    private void maybeRecreateClassifierCheckConstraintsForMssql(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            statement.execute("""
                    SELECT OBJ."NAME" AS TABLE_NAME
                         , COL."NAME" AS COLUMN_NAME
                         , CON."NAME" AS NAME
                         , CON."DEFINITION" AS DEFINITION
                      FROM SYS.CHECK_CONSTRAINTS AS CON
                      LEFT JOIN SYS.OBJECTS AS OBJ
                        ON OBJ.OBJECT_ID = CON.PARENT_OBJECT_ID
                      LEFT JOIN SYS.ALL_COLUMNS AS COL
                        ON COL.COLUMN_ID = CON.PARENT_COLUMN_ID
                       AND COL.OBJECT_ID = CON.PARENT_OBJECT_ID
                     WHERE OBJ."NAME" IN ('COMPONENT', 'PROJECT')
                       AND COL."NAME" = 'CLASSIFIER'
                    """);

            final var constraints = new ArrayList<ClassifierConstraint>();

            try (final ResultSet rs = statement.getResultSet()) {
                while (rs.next()) {
                    constraints.add(ClassifierConstraint.of(rs));
                }
            }

            for (final ClassifierConstraint constraint : constraints) {
                if (constraint.isCurrent()) {
                    LOGGER.info("Constraint %s on table %s is already current; Will not re-create".formatted(
                            constraint.name(), constraint.tableName()));
                    continue;
                }

                LOGGER.info("Constraint %s on table %s is outdated; Recreating".formatted(
                        constraint.name(), constraint.tableName()));

                statement.execute("ALTER TABLE \"%s\" DROP CONSTRAINT \"%s\"".formatted(
                        constraint.tableName(), constraint.name()));

                statement.execute("ALTER TABLE \"%s\" ADD CONSTRAINT \"%s\" CHECK %s".formatted(
                        constraint.tableName(), constraint.name(), classifierCheckConstraint()));
            }
        }
    }

    private void maybeRecreateClassifierCheckConstraintsForPostgres(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            statement.execute("""
                    SELECT CON.CONNAME AS "NAME"
                         , PG_GET_CONSTRAINTDEF(CON.OID) AS "DEFINITION"
                         , CCU.TABLE_NAME AS "TABLE_NAME"
                         , CCU.COLUMN_NAME AS "COLUMN_NAME"
                      FROM PG_CONSTRAINT AS CON
                     INNER JOIN PG_NAMESPACE  AS NS
                        ON NS.OID = CON.CONNAMESPACE
                     INNER JOIN PG_CLASS AS CLS
                        ON CLS.OID = CON.CONRELID
                      LEFT JOIN INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE AS CCU
                        ON CCU.CONSTRAINT_NAME = CON.CONNAME
                       AND CCU.CONSTRAINT_SCHEMA = NS.NSPNAME
                     WHERE CON.CONTYPE = 'c'
                       AND CCU.TABLE_NAME IN ('COMPONENT', 'PROJECT')
                       AND CCU.COLUMN_NAME = 'CLASSIFIER'
                    """);

            final var constraints = new ArrayList<ClassifierConstraint>();

            try (final ResultSet rs = statement.getResultSet()) {
                while (rs.next()) {
                    constraints.add(ClassifierConstraint.of(rs));
                }
            }

            for (final ClassifierConstraint constraint : constraints) {
                if (constraint.isCurrent()) {
                    LOGGER.info("Constraint %s on table %s is already current; Will not re-create".formatted(
                            constraint.name(), constraint.tableName()));
                    continue;
                }

                LOGGER.info("Constraint %s on table %s is outdated; Recreating".formatted(
                        constraint.name(), constraint.tableName()));

                statement.execute("ALTER TABLE \"%s\" DROP CONSTRAINT \"%s\"".formatted(
                        constraint.tableName(), constraint.name()));

                statement.execute("ALTER TABLE \"%s\" ADD CONSTRAINT \"%s\" CHECK %s".formatted(
                        constraint.tableName(), constraint.name(), classifierCheckConstraint()));
            }
        }
    }

    private static String classifierCheckConstraint() {
        final var classifierArrayLiteralJoiner = new StringJoiner(",", "(", ")");
        for (final Classifier classifier : Classifier.values()) {
            classifierArrayLiteralJoiner.add("'%s'".formatted(classifier.name()));
        }

        return "(\"CLASSIFIER\" IS NULL OR \"CLASSIFIER\" IN %s)".formatted(classifierArrayLiteralJoiner);
    }

}
