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
package org.dependencytrack.persistence;

import alpine.config.AlpineConfigKeys;
import alpine.server.auth.PasswordService;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.apache.commons.lang3.SerializationUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.DefaultRepository;
import org.dependencytrack.model.License;
import org.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Update;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_DEFAULT_OBJECTS_VERSION;

/**
 * @since 5.0.0
 */
public final class DatabaseSeedingInitTask implements InitTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseSeedingInitTask.class);

    private static final Map<String, List<String>> DEFAULT_TEAM_PERMISSIONS = Map.of(
            "Administrators", Stream.of(Permissions.values())
                    .map(Permissions::name)
                    .toList(),
            "Portfolio Managers", List.of(
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_READ,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE),
            "Automation", List.of(
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.BOM_UPLOAD));

    @Override
    public int priority() {
        return PRIORITY_HIGHEST - 10;
    }

    @Override
    public String name() {
        return "database-seeding";
    }

    @Override
    public void execute(final InitTaskContext ctx) throws Exception {
        final var jdbi = JdbiFactory.createLocalJdbi(ctx.dataSource());

        jdbi.useTransaction(handle -> {
            final var configPropertyDao = handle.attach(ConfigPropertyDao.class);

            final String appBuildUuid = ctx.config().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_UUID, String.class);
            final String appBuildTimestamp = ctx.config().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_TIMESTAMP, String.class);
            final String defaultObjectsVersion = configPropertyDao
                    .getOptionalValue(INTERNAL_DEFAULT_OBJECTS_VERSION)
                    .orElse(null);
            if (appBuildUuid.equals(defaultObjectsVersion)) {
                LOGGER.info(
                        "Default objects already populated for build {} (timestamp: {}); Skipping",
                        appBuildUuid,
                        appBuildTimestamp);
                return;
            }

            seedDefaultConfigProperties(handle);
            seedDefaultPermissions(handle);
            seedDefaultLicenses(handle);
            seedDefaultRepositories(handle);

            final boolean isFirstExecution = defaultObjectsVersion == null;
            if (isFirstExecution) {
                seedDefaultTeams(handle);
                seedDefaultUsers(handle);
                seedDefaultLicenseGroups(handle);
            }

            configPropertyDao.setValue(
                    INTERNAL_DEFAULT_OBJECTS_VERSION,
                    appBuildUuid);
        });
    }

    public static void seedDefaultConfigProperties(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "CONFIGPROPERTY" ("GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE", "DESCRIPTION")
                VALUES (:groupName, :propertyName, :propertyType, :defaultPropertyValue, :description)
                ON CONFLICT ("GROUPNAME", "PROPERTYNAME") DO NOTHING
                """);

        for (final ConfigPropertyConstants configProperty : ConfigPropertyConstants.values()) {
            preparedBatch.bindBean(configProperty);
            preparedBatch.add();
        }

        final int configPropertiesCreated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created {} config properties", configPropertiesCreated);
    }

    public static void seedDefaultPermissions(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "PERMISSION" ("NAME", "DESCRIPTION")
                VALUES (:name, :description)
                ON CONFLICT ("NAME") DO NOTHING
                """);

        for (final Permissions permission : Permissions.values()) {
            preparedBatch.bind("name", permission.name());
            preparedBatch.bind("description", permission.getDescription());
            preparedBatch.add();
        }

        final int permissionsCreated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created {} permissions", permissionsCreated);
    }

    public static void seedDefaultTeams(final Handle jdbiHandle) {
        final Update update = jdbiHandle.createUpdate("""
                WITH cte_team_permission AS (
                  SELECT *
                    FROM UNNEST(:teamNames, :permissionNames) AS t(team_name, permission_name)
                ),
                cte_created_team AS (
                  INSERT INTO "TEAM" ("NAME", "UUID")
                  SELECT DISTINCT ON (team_name)
                         team_name
                       , GEN_RANDOM_UUID()
                    FROM cte_team_permission
                  ON CONFLICT ("NAME") DO NOTHING
                  RETURNING "ID" AS id
                          , "NAME" AS name
                )
                INSERT INTO "TEAMS_PERMISSIONS" ("TEAM_ID", "PERMISSION_ID")
                SELECT cte_created_team.id
                     , (SELECT "ID" FROM "PERMISSION" WHERE "NAME" = cte_team_permission.permission_name)
                  FROM cte_team_permission
                 INNER JOIN cte_created_team
                    ON cte_created_team.name = cte_team_permission.team_name
                """);

        final var teamNames = new ArrayList<String>();
        final var permissionNames = new ArrayList<String>();

        for (final Map.Entry<String, List<String>> entry : DEFAULT_TEAM_PERMISSIONS.entrySet()) {
            for (final String permissionName : entry.getValue()) {
                teamNames.add(entry.getKey());
                permissionNames.add(permissionName);
            }
        }

        update
                .bindArray("teamNames", String.class, teamNames)
                .bindArray("permissionNames", String.class, permissionNames)
                .execute();
    }

    public static void seedDefaultUsers(final Handle jdbiHandle) {
        final Optional<Long> adminUserId = jdbiHandle.createUpdate("""
                        INSERT INTO "USER" (
                          "TYPE", "USERNAME", "EMAIL", "PASSWORD", "LAST_PASSWORD_CHANGE"
                        , "FORCE_PASSWORD_CHANGE", "NON_EXPIRY_PASSWORD", "SUSPENDED")
                        VALUES ('MANAGED', 'admin', 'admin@localhost', :password, NOW(), TRUE, TRUE, FALSE)
                        ON CONFLICT ("USERNAME") DO NOTHING
                        RETURNING "ID"
                        """)
                .bind("password", new String(PasswordService.createHash("admin".toCharArray())))
                .executeAndReturnGeneratedKeys()
                .mapTo(Long.class)
                .findOne();

        if (adminUserId.isEmpty()) {
            LOGGER.debug("Default 'admin' user already exists; skipping team/permission seeding");
            return;
        }

        jdbiHandle.createUpdate("""
                        INSERT INTO "USERS_TEAMS" ("USER_ID", "TEAM_ID")
                        SELECT :adminUserId, (SELECT "ID" FROM "TEAM" WHERE "NAME" = 'Administrators')
                        """)
                .bind("adminUserId", adminUserId.get())
                .execute();

        jdbiHandle.createUpdate("""
                        INSERT INTO "USERS_PERMISSIONS" ("USER_ID", "PERMISSION_ID")
                        SELECT :adminUserId, "PERMISSION"."ID" FROM "PERMISSION"
                        """)
                .bind("adminUserId", adminUserId.get())
                .execute();
    }

    public static void seedDefaultLicenses(final Handle jdbiHandle) {
        final List<License> licenses;
        try {
            licenses = new SpdxLicenseDetailParser().getLicenseDefinitions();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load license details", e);
        }

        // We have hundreds of licenses, the majority of which is *very* unlikely to change between executions
        // of this init task. In the future, we should store the version of the SPDX license list,
        // and then only sync licenses when that version has changed.
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "LICENSE" (
                  "LICENSEID", "NAME", "HEADER", "TEXT", "TEMPLATE", "ISDEPRECATED"
                , "FSFLIBRE", "ISOSIAPPROVED", "COMMENT", "SEEALSO", "UUID"
                )
                VALUES (
                  :licenseId, :name, :header, :text, :template, :deprecatedLicenseId
                , :fsfLibre, :osiApproved, :comment, :seeAlsoSerialized, GEN_RANDOM_UUID()
                )
                ON CONFLICT ("LICENSEID") DO UPDATE
                SET "NAME" = EXCLUDED."NAME"
                  , "HEADER" = EXCLUDED."HEADER"
                  , "TEXT" = EXCLUDED."TEXT"
                  , "TEMPLATE" = EXCLUDED."TEMPLATE"
                  , "ISDEPRECATED" = EXCLUDED."ISDEPRECATED"
                  , "FSFLIBRE" = EXCLUDED."FSFLIBRE"
                  , "ISOSIAPPROVED" = EXCLUDED."ISOSIAPPROVED"
                  , "COMMENT" = EXCLUDED."COMMENT"
                  , "SEEALSO" = EXCLUDED."SEEALSO"
                -- Only update when at least one relevant field has changed.
                WHERE "LICENSE"."NAME" IS DISTINCT FROM EXCLUDED."NAME"
                   OR "LICENSE"."HEADER" IS DISTINCT FROM EXCLUDED."HEADER"
                   OR "LICENSE"."TEXT" IS DISTINCT FROM EXCLUDED."TEXT"
                   OR "LICENSE"."TEMPLATE" IS DISTINCT FROM EXCLUDED."TEMPLATE"
                   OR "LICENSE"."ISDEPRECATED" IS DISTINCT FROM EXCLUDED."ISDEPRECATED"
                   OR "LICENSE"."FSFLIBRE" IS DISTINCT FROM EXCLUDED."FSFLIBRE"
                   OR "LICENSE"."ISOSIAPPROVED" IS DISTINCT FROM EXCLUDED."ISOSIAPPROVED"
                   OR "LICENSE"."COMMENT" IS DISTINCT FROM EXCLUDED."COMMENT"
                   OR "LICENSE"."SEEALSO" IS DISTINCT FROM EXCLUDED."SEEALSO"
                """);

        for (final License license : licenses) {
            preparedBatch.bindBean(license);
            preparedBatch.bind(
                    "seeAlsoSerialized",
                    license.getSeeAlso() != null
                            ? SerializationUtils.serialize(license.getSeeAlso())
                            : null);
            preparedBatch.add();
        }

        int licensesCreatedOrUpdated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created or updated {} licenses", licensesCreatedOrUpdated);
    }

    public static void seedDefaultLicenseGroups(final Handle jdbiHandle) {
        // NB: LICENSEGROUP has no UNIQUE constraint on NAME (only on UUID),
        // so ON CONFLICT can't be used. Guard with WHERE NOT EXISTS instead.
        final Update update = jdbiHandle.createUpdate("""
                WITH cte_group_license AS (
                  SELECT *
                    FROM UNNEST(:groupNames, :groupRiskWeights, :licenseIds) AS t(group_name, group_risk_weight, license_id)
                ),
                cte_created_group AS (
                  INSERT INTO "LICENSEGROUP" ("NAME", "RISKWEIGHT", "UUID")
                  SELECT DISTINCT ON (group_name)
                         group_name
                       , group_risk_weight
                       , GEN_RANDOM_UUID()
                    FROM cte_group_license
                   WHERE NOT EXISTS (
                       SELECT 1 FROM "LICENSEGROUP" lg WHERE lg."NAME" = cte_group_license.group_name)
                  RETURNING "ID" AS id, "NAME" AS name
                )
                INSERT INTO "LICENSEGROUP_LICENSE" ("LICENSEGROUP_ID", "LICENSE_ID")
                SELECT cte_created_group.id
                     , (SELECT "ID" FROM "LICENSE" WHERE "LICENSEID" = cte_group_license.license_id)
                  FROM cte_group_license
                 INNER JOIN cte_created_group
                    ON cte_created_group.name = cte_group_license.group_name
                """);

        final JsonArray groupDefsJson;
        try (final InputStream inputStream = DatabaseSeedingInitTask.class.getResourceAsStream("/default-objects/licenseGroups.json");
             final JsonReader jsonReader = Json.createReader(inputStream)) {
            groupDefsJson = jsonReader.readArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse license group definition", e);
        }

        final var groupNames = new ArrayList<String>();
        final var groupRiskWeights = new ArrayList<Integer>();
        final var licenseIds = new ArrayList<String>();

        for (int i = 0; i < groupDefsJson.size(); i++) {
            final JsonObject groupDefJson = groupDefsJson.getJsonObject(i);
            final String groupName = groupDefJson.getString("name");
            final int riskWeight = groupDefJson.getInt("riskWeight");

            final JsonArray licenseIdsJson = groupDefJson.getJsonArray("licenses");
            for (int j = 0; j < licenseIdsJson.size(); j++) {
                groupNames.add(groupName);
                groupRiskWeights.add(riskWeight);
                licenseIds.add(licenseIdsJson.getString(j));
            }
        }

        update
                .bindArray("groupNames", String.class, groupNames)
                .bindArray("groupRiskWeights", Integer.class, groupRiskWeights)
                .bindArray("licenseIds", String.class, licenseIds)
                .execute();
    }

    public static void seedDefaultRepositories(final Handle jdbiHandle) {
        final PreparedBatch preparedBatch = jdbiHandle.prepareBatch("""
                INSERT INTO "REPOSITORY"(
                  "TYPE", "IDENTIFIER", "URL", "INTERNAL", "RESOLUTION_ORDER"
                , "ENABLED", "AUTHENTICATIONREQUIRED", "UUID")
                VALUES (
                  :type, :identifier, :url, FALSE, :resolutionOrder
                , TRUE, FALSE, GEN_RANDOM_UUID())
                ON CONFLICT ("TYPE", "IDENTIFIER") DO NOTHING
                """);

        for (final DefaultRepository repository : DefaultRepository.values()) {
            preparedBatch.bindBean(repository);
            preparedBatch.add();
        }

        final int reposCreated = Arrays.stream(preparedBatch.execute()).sum();
        LOGGER.debug("Created {} repositories", reposCreated);
    }

}
