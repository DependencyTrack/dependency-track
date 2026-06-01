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
package org.dependencytrack.v4migrator;

import org.jdbi.v3.core.Jdbi;

/**
 * Seeds the v5 {@code PERMISSION} catalog from the apiserver's
 * {@code org.dependencytrack.auth.Permissions} enum at Flyway head
 * {@code 202605111028}. Keep this in sync with the enum.
 *
 * <p>The migrator owns v5 PERMISSION seeding because downstream join-table loads
 * ({@code USERS_PERMISSIONS}, {@code TEAMS_PERMISSIONS}) need to FK-resolve v5
 * permission IDs (including v5-only entries such as
 * {@code PORTFOLIO_ACCESS_CONTROL_BYPASS}) before the apiserver runs its own
 * seeding step on first post-migration boot.
 *
 * <p>Seeding runs in {@code bootstrap} rather than {@code transform} so that a
 * documented "drop v5 schema, re-bootstrap, re-run load" recovery (see ADR-023
 * §Resumability and the user-facing migration guide) leaves PERMISSION populated
 * without re-running {@code transform}. The INSERT uses
 * {@code ON CONFLICT ("NAME") DO NOTHING} and is safe to invoke repeatedly.
 */
public final class PermissionCatalog {

    private static final String SEED_SQL = """
        INSERT INTO "PERMISSION" ("NAME", "DESCRIPTION") VALUES
            ('BOM_UPLOAD', 'Allows the ability to upload CycloneDX Software Bill of Materials (SBOM)'),
            ('VIEW_PORTFOLIO', 'Provides the ability to view the portfolio of projects, components, and licenses'),
            ('PORTFOLIO_ACCESS_CONTROL_BYPASS', 'Provides the ability to bypass portfolio access control, granting access to all projects'),
            ('PORTFOLIO_MANAGEMENT', 'Allows the creation, modification, and deletion of data in the portfolio'),
            ('PORTFOLIO_MANAGEMENT_CREATE', 'Allows the creation of data in the portfolio'),
            ('PORTFOLIO_MANAGEMENT_READ', 'Allows the reading of data in the portfolio'),
            ('PORTFOLIO_MANAGEMENT_UPDATE', 'Allows the updating of data in the portfolio'),
            ('PORTFOLIO_MANAGEMENT_DELETE', 'Allows the deletion of data in the portfolio'),
            ('VIEW_VULNERABILITY', 'Provides the ability to view the vulnerabilities projects are affected by'),
            ('VULNERABILITY_ANALYSIS', 'Provides all abilities to make analysis decisions on vulnerabilities'),
            ('VULNERABILITY_ANALYSIS_CREATE', 'Provides the ability to upload supported VEX documents to a project'),
            ('VULNERABILITY_ANALYSIS_READ', 'Provides the ability read the VEX document for a project'),
            ('VULNERABILITY_ANALYSIS_UPDATE', 'Provides the ability to make analysis decisions on vulnerabilities and upload supported VEX documents for a project'),
            ('VIEW_POLICY_VIOLATION', 'Provides the ability to view policy violations'),
            ('VULNERABILITY_MANAGEMENT', 'Allows all management permissions of internally-defined vulnerabilities'),
            ('VULNERABILITY_MANAGEMENT_CREATE', 'Allows creation of internally-defined vulnerabilities'),
            ('VULNERABILITY_MANAGEMENT_READ', 'Allows reading internally-defined vulnerabilities'),
            ('VULNERABILITY_MANAGEMENT_UPDATE', 'Allows updating internally-defined vulnerabilities and vulnerability tags'),
            ('VULNERABILITY_MANAGEMENT_DELETE', 'Allows management of internally-defined vulnerabilities'),
            ('POLICY_VIOLATION_ANALYSIS', 'Provides the ability to make analysis decisions on policy violations'),
            ('ACCESS_MANAGEMENT', 'Allows the management of users, teams, and API keys'),
            ('ACCESS_MANAGEMENT_CREATE', 'Allows create permissions of users, teams, and API keys'),
            ('ACCESS_MANAGEMENT_READ', 'Allows read permissions of users, teams, and API keys'),
            ('ACCESS_MANAGEMENT_UPDATE', 'Allows update permissions of users, teams, and API keys'),
            ('ACCESS_MANAGEMENT_DELETE', 'Allows delete permissions of users, teams, and API keys'),
            ('SECRET_MANAGEMENT', 'Grants full secret management access'),
            ('SECRET_MANAGEMENT_CREATE', 'Grants the ability to create secrets'),
            ('SECRET_MANAGEMENT_UPDATE', 'Grants the ability to update secrets'),
            ('SECRET_MANAGEMENT_DELETE', 'Grants the ability to delete secrets'),
            ('SYSTEM_CONFIGURATION', 'Allows all access to configuration of the system including notifications, repositories, and email settings'),
            ('SYSTEM_CONFIGURATION_CREATE', 'Allows creating configuration of the system including notifications, repositories, and email settings'),
            ('SYSTEM_CONFIGURATION_READ', 'Allows reading the configuration of the system including notifications, repositories, and email settings'),
            ('SYSTEM_CONFIGURATION_UPDATE', 'Allows updating the configuration of the system including notifications, repositories, and email settings'),
            ('SYSTEM_CONFIGURATION_DELETE', 'Allows deleting the configuration of the system including notifications, repositories, and email settings'),
            ('PROJECT_CREATION_UPLOAD', 'Provides the ability to optionally create project (if non-existent) on BOM or scan upload'),
            ('POLICY_MANAGEMENT', 'Allows the creation, modification, and deletion of policy'),
            ('POLICY_MANAGEMENT_CREATE', 'Allows the creation of a policy'),
            ('POLICY_MANAGEMENT_READ', 'Allows reading of policies'),
            ('POLICY_MANAGEMENT_UPDATE', 'Allows the modification of a policy'),
            ('POLICY_MANAGEMENT_DELETE', 'Allows the deletion of a policy'),
            ('TAG_MANAGEMENT', 'Allows the modification and deletion of tags'),
            ('TAG_MANAGEMENT_DELETE', 'Allows the deletion of a tag')
        ON CONFLICT ("NAME") DO NOTHING
        """;

    private PermissionCatalog() {
    }

    public static int seed(final Jdbi target) {
        return target.withHandle(h -> h.execute(SEED_SQL));
    }
}
